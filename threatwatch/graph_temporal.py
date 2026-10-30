"""Point-in-time *context*, not propagation of victimhood or breach probabilities.

Edges are counted only if manually verified and recorded before the forecast
cutoff. Media statements are not successful breaches. Every counted item must
have been published AND collected before the cutoff; synthetic items excluded.
"""
from __future__ import annotations
import csv
import datetime as dt
from pathlib import Path
from .normalize import UTC
from .history import point_in_time_features, _healthy_window, date_from
from .calibration import FEATURES

GRAPH_FEATURES = ('documented_neighbors','neighbor_claims_14d',
                  'sector_claims_14d','country_claims_14d')
GRAPH_FIELDS = ['as_of_date','org_id',*FEATURES,*GRAPH_FEATURES,'incident_next_14d',
                'label_status','outcome_evidence_url','outcome_notes','observed_until','snapshot_mode']


def _as_date(date: dt.date | str) -> dt.date:
    return dt.date.fromisoformat(date) if isinstance(date,str) else date


def graph_context_at(con, org_id: str, as_of: dt.date | str) -> dict:
    """Context from public statements only; NOT an individual probability.

    Withholding review_status is deliberate: historic review changes were not
    timestamped in earlier versions, therefore using it would leak the future.
    """
    as_of = _as_date(as_of)
    if not con.execute('SELECT 1 FROM organizations WHERE id=?',(org_id,)).fetchone():
        raise ValueError('Unknown organization')
    cutoff=as_of.isoformat()+'T23:59:59.999999+00:00'
    start=(as_of-dt.timedelta(days=14)).isoformat()+'T00:00:00+00:00'
    edges=con.execute('''SELECT DISTINCT
      CASE WHEN source_org_id=? THEN target_org_id ELSE source_org_id END AS neighbor
      FROM organization_relations WHERE (source_org_id=? OR target_org_id=?)
      AND review_status='verified' AND recorded_at<=? AND verified_at IS NOT NULL AND verified_at<=?''',
      (org_id,org_id,org_id,cutoff,cutoff)).fetchall()
    neighbors={r['neighbor'] for r in edges}
    # Count DISTINCT source-group/date/organization combinations to dampen
    # syndicated copies; no raw article count is presented as successful attacks.
    rows=con.execute('''SELECT m.org_id,i.source_group,substr(i.published_at,1,10) AS day,
         o.sector,o.country
      FROM mentions m JOIN items i ON i.id=m.item_id
      JOIN organizations o ON o.id=m.org_id
      WHERE i.published_at>=? AND i.published_at<=? AND i.collected_at<=?
        AND i.origin!='synthetic' AND i.kind IN ('claim','threat_statement','incident_report')
        AND m.org_id!=? AND m.linked_at IS NOT NULL AND m.linked_at<=?''',(start,cutoff,cutoff,org_id,cutoff)).fetchall()
    focal=con.execute('SELECT sector,country FROM organizations WHERE id=?',(org_id,)).fetchone()
    # Keys are distinct organizations on distinct days from distinct publisher
    # groups. A group asserting an attack is NOT independent incident validation.
    neighbor=set(); sector=set(); country=set()
    for row in rows:
        event=(row['org_id'],row['source_group'],row['day'])
        if row['org_id'] in neighbors: neighbor.add(event)
        if row['sector'] and row['sector']==focal['sector']: sector.add(event)
        if row['country'] and row['country']==focal['country']: country.add(event)
    return {'as_of_date':as_of.isoformat(),'org_id':org_id,
            'documented_neighbors':min(5,len(neighbors)),
            'neighbor_claims_14d':min(5,len(neighbor)),
            'sector_claims_14d':min(5,len(sector)),
            'country_claims_14d':min(5,len(country)),
            'raw_counts':{'documented_neighbors':len(neighbors),'neighbor_publication_groups':len(neighbor),
                          'sector_publication_groups':len(sector),'country_publication_groups':len(country)},
            'limitations':'Context signals are media/attacker claims, not successful compromises. '
                          'Relationships are included only if verified and recorded by the as-of date.'}


def prepare_graph_history(con, output: Path, *, start=None,end=None,step_days=7,
                          today:dt.date | None=None,mode='strict') -> dict:
    if mode!='strict':
        raise ValueError('Graph model only supports strict point-in-time snapshots')
    if not 1<=step_days<=90: raise ValueError('step_days must be 1..90')
    today=today or dt.datetime.now(UTC).date()
    end_date=date_from(end) or today-dt.timedelta(days=14)
    if end_date+dt.timedelta(days=14)>today:
        raise ValueError('The full 14-day outcome window must have elapsed')
    if start:
        start_date=date_from(start)
    else:
        first=con.execute("SELECT MIN(checked_at) FROM source_checks WHERE status='ok'").fetchone()[0]
        start_date=dt.date.fromisoformat(first[:10])+dt.timedelta(days=28) if first else end_date+dt.timedelta(days=1)
    if (end_date-start_date).days>3650:
        raise ValueError('Refusing to produce more than 10 years of snapshots')
    output.parent.mkdir(parents=True,exist_ok=True)
    count=0;days=0;skipped=0
    with output.open('w',encoding='utf-8-sig',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=GRAPH_FIELDS); writer.writeheader()
        date=start_date
        orgs=con.execute('SELECT id FROM organizations ORDER BY id').fetchall()
        while date<=end_date:
            if not _healthy_window(con,date):
                skipped+=1;date+=dt.timedelta(days=step_days);continue
            days+=1
            for org in orgs:
                # Existing candidate approvals created before v5 did not record
                # review timestamps; do not backdate eligibility for such nodes.
                try:
                    candidate=con.execute('''SELECT reviewed_at,first_seen FROM entity_candidates
                       WHERE reviewed_org_id=? LIMIT 1''',(org['id'],)).fetchone()
                except Exception:
                    candidate=None
                if candidate:
                    approved_at=candidate['reviewed_at']
                    if not approved_at or approved_at[:10]>date.isoformat():
                        continue
                base=point_in_time_features(con,org['id'],date,mode='strict',require_link_provenance=True)
                graph=graph_context_at(con,org['id'],date)
                row={'as_of_date':date.isoformat(),'org_id':org['id'],
                     **dict(zip(FEATURES,base)),
                     **{k:graph[k] for k in GRAPH_FEATURES},
                     'incident_next_14d':'','label_status':'UNLABELLED_REQUIRES_INDEPENDENT_REVIEW',
                     'outcome_evidence_url':'','outcome_notes':'',
                     'observed_until':(date+dt.timedelta(days=14)).isoformat(),
                     'snapshot_mode':'strict_observed'}
                writer.writerow(row);count+=1
            date+=dt.timedelta(days=step_days)
    return {'status':'candidate_snapshots_unlabelled' if count else 'insufficient_historical_coverage',
            'rows':count,'snapshot_dates':days,'skipped_dates':skipped,'output':str(output),
            'warning':'No breach or non-breach labels have been inferred. Outcomes require independent observation; do not treat silence as a negative.'}
