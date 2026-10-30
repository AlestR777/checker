"""Point-in-time historical features for DEFENSIVE incident forecasting research.

Default strict mode uses *ingestion* timestamps, not just publication dates. An
article published on 3 October but first collected on 29 October cannot be used
as a feature for a prediction allegedly made on 10 October. This is critical to
prevent look-ahead leakage in retrospective OSINT.

Outcomes are NEVER inferred from absences in a news database. Both positives and
negatives require a separate independent confirmation process. The CSV leaves
outcome labels empty and is not a trained model.
"""
from __future__ import annotations
import csv
import datetime as dt
from pathlib import Path
from .normalize import UTC
from .calibration import FEATURES

# Feature names must exactly match the existing time-split classifier.
FIELDS = ["as_of_date", "org_id", *FEATURES, "incident_next_14d",
          "label_status", "outcome_evidence_url", "outcome_notes", "observed_until", "snapshot_mode"]
SIGNAL_KINDS={"claim", "threat_statement", "incident_report"}


def date_from(value: str | None) -> dt.date | None:
    return dt.date.fromisoformat(value) if value else None


def point_in_time_features(con, org_id: str, as_of: dt.date, *, mode="strict", require_link_provenance=False) -> list[int]:
    """Derive 8 bounded features without reading content ingested after the cutoff.

    Review status is omitted from historical features because review timestamp
    is not stored in old v3.1 databases. A later review cannot be backdated.
    """
    if mode not in {"strict","retrospective"}:
        raise ValueError("Unknown mode")
    cutoff=as_of.isoformat()+"T23:59:59.999999+00:00"
    start=(as_of-dt.timedelta(days=28)).isoformat()+"T00:00:00+00:00"
    where="AND i.collected_at<=?" if mode=="strict" else ""
    params=[org_id,start,cutoff]+([cutoff] if mode=="strict" else [])
    if require_link_provenance:
        where+=' AND m.linked_at IS NOT NULL AND m.linked_at<=?'
        params.append(cutoff)
    rows=con.execute(f"""SELECT i.id,i.kind,i.published_at,i.collected_at,
                  i.source_group,c.id AS cluster_id
      FROM items i JOIN mentions m ON m.item_id=i.id
      LEFT JOIN cluster_members cm ON cm.item_id=i.id
      LEFT JOIN clusters c ON c.id=cm.cluster_id AND c.org_id=m.org_id
      WHERE m.org_id=? AND i.published_at>=? AND i.published_at<=?
       {where} AND i.origin!='synthetic' AND i.kind IN ('claim','incident_report','threat_statement')
       AND (c.org_id=? OR cm.cluster_id IS NULL)
      ORDER BY i.published_at DESC""",params+[org_id]).fetchall()
    # Event consolidation per group, including multiple publications per event.
    current={}; previous={}
    for r in rows:
        day=dt.date.fromisoformat(r["published_at"][:10])
        elapsed=(as_of-day).days
        if elapsed<0 or elapsed>28:
            continue
        dest=current if elapsed<=14 else previous
        key=str(r['cluster_id'] or 'item-'+str(r['id']))
        dest.setdefault(key,[]).append(r)
    current_rows=[r for g in current.values() for r in g]
    source_groups={r['source_group'] for r in current_rows if r['source_group']}
    direct=sum(any(r['kind']=='threat_statement' for r in group) for group in current.values())
    claims=sum(any(r['kind']=='claim' for r in group) for group in current.values())
    unique_days={r['published_at'][:10] for r in current_rows}
    def weight(group):
        return max((1.5 if x['kind']=='threat_statement' else
                    1.0 if x['kind']=='claim' else .8) for x in group)
    current_weight=sum(weight(g) for g in current.values())
    previous_weight=sum(weight(g) for g in previous.values())
    freshness=0
    if current_rows:
        age=min((as_of-dt.date.fromisoformat(r['published_at'][:10])).days for r in current_rows)
        freshness=5 if age<=2 else 4 if age<=5 else 3 if age<=9 else 2
    # Historical sector context: same query with both publication and ingestion cutoffs.
    peers_where="AND i.collected_at<=?" if mode=="strict" else ""
    peer_args=[org_id,org_id,(as_of-dt.timedelta(days=14)).isoformat()+"T00:00:00+00:00",cutoff]
    if mode=="strict":peer_args.append(cutoff)
    if require_link_provenance:
        peers_where+=' AND m.linked_at IS NOT NULL AND m.linked_at<=?'
        peer_args.append(cutoff)
    other=con.execute(f"""SELECT count(DISTINCT c.id) FROM clusters c
      JOIN organizations peer ON peer.id=c.org_id
      JOIN organizations target ON target.id=? AND target.sector=peer.sector
      JOIN cluster_members cm ON cm.cluster_id=c.id JOIN items i ON i.id=cm.item_id
      JOIN mentions m ON m.item_id=i.id AND m.org_id=c.org_id
      WHERE c.org_id!=? AND i.published_at>=? AND i.published_at<=? {peers_where}
        AND i.origin!='synthetic' AND i.kind IN ('claim','threat_statement','incident_report')""",peer_args).fetchone()[0]
    return [min(5,2*direct),min(5,claims),min(5,max(0,len(source_groups)-1)*2),
            min(5,int(max(0,current_weight-previous_weight)*1.2)),freshness,
            min(5,max(0,len(unique_days)-1)*2),min(5,int(other)),0]


def _healthy_window(con, date: dt.date, min_days=28) -> bool:
    """Reject immature observation windows and historical replays by default."""
    begin=(date-dt.timedelta(days=min_days)).isoformat()+"T00:00:00"
    end=date.isoformat()+"T23:59:59"
    checks=con.execute("""SELECT MIN(checked_at) AS first,MAX(checked_at) AS last,
            COUNT(DISTINCT substr(checked_at,1,10)) AS days,
            COUNT(DISTINCT source_group) AS groups
            FROM source_checks WHERE status='ok' AND checked_at BETWEEN ? AND ?""",
            (begin,end)).fetchone()
    if not checks['first'] or not checks['last']:
        return False
    first=dt.date.fromisoformat(checks['first'][:10]); last=dt.date.fromisoformat(checks['last'][:10])
    # Require >~4 weekly collection points, at least 2 source families, and a
    # genuinely observed 28-day feature window (not backfilled RSS yesterday).
    return ((last-first).days>=min_days-2 and
            checks['days']>=5 and checks['groups']>=2 and
            (date-last).days<=2 and (first-dt.date.fromisoformat(begin[:10])).days<=2)


def prepare_history(con, output: Path, *, start=None, end=None, step_days=7,
                    mode='strict', today: dt.date | None=None, horizon_days=14) -> dict:
    """Export candidate snapshots; do not fabricate either attack or no-attack labels."""
    if mode not in {'strict','retrospective'}:
        raise ValueError('Unknown mode')
    if step_days < 1 or step_days > 90:
        raise ValueError('step-days must be from 1 to 90')
    today=today or dt.datetime.now(UTC).date()
    end_date=date_from(end) or (today-dt.timedelta(days=horizon_days))
    if end_date+dt.timedelta(days=horizon_days)>today:
        raise ValueError('The 14-day outcome window must be fully elapsed')
    if start:
        start_date=date_from(start)
    else:
        r=con.execute("SELECT MIN(checked_at) FROM source_checks WHERE status='ok'").fetchone()[0]
        if not r:
            r=con.execute("SELECT MIN(collected_at) FROM items WHERE origin!='synthetic'").fetchone()[0]
        start_date=(dt.date.fromisoformat(r[:10])+dt.timedelta(days=28)) if r else end_date+dt.timedelta(days=1)
    if (end_date-start_date).days>3650:
        raise ValueError('Specify a smaller date range (at most 10 years)')
    output.parent.mkdir(parents=True,exist_ok=True)
    total=0; skipped=0; dates=[]
    with output.open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=FIELDS); w.writeheader()
        cur=start_date
        orgs=con.execute('SELECT id FROM organizations ORDER BY id').fetchall()
        while cur<=end_date:
            if mode=='strict' and not _healthy_window(con,cur):
                skipped+=1;cur+=dt.timedelta(days=step_days);continue
            for org in orgs:
                vals=point_in_time_features(con,org['id'],cur,mode=mode)
                row={'as_of_date':cur.isoformat(),'org_id':org['id'],
                     'incident_next_14d':'','label_status':'UNLABELLED_REQUIRES_INDEPENDENT_REVIEW',
                     'outcome_evidence_url':'','outcome_notes':'',
                     'observed_until':(cur+dt.timedelta(days=horizon_days)).isoformat(),
                     'snapshot_mode': 'strict_observed' if mode=='strict' else 'retrospective_not_for_training'}
                row.update(dict(zip(FEATURES,vals)))
                w.writerow(row);total+=1
            dates.append(cur.isoformat());cur+=dt.timedelta(days=step_days)
    return {'status':('candidate_snapshots_unlabelled' if total else 'insufficient_historical_coverage'),
            'rows':total,'snapshot_dates':len(dates),'dates_skipped_no_28d_coverage':skipped,
            'organizations':con.execute('SELECT COUNT(*) FROM organizations').fetchone()[0],
            'mode':mode,'output':str(output),
            'next_step':'Manually verify both positive AND negative outcomes with independent evidence; then validate-model.',
            'warning':('Retrospective mode may contain publication look-ahead from later collection; do NOT train on these snapshots.' if mode=='retrospective' else
                       'Strict mode uses only observations collected by each as-of date. No missing incident is automatically a negative.')}


def readiness(con, *, today: dt.date | None=None) -> dict:
    """Basic readiness to assemble STRICT historical feature/outcome windows."""
    today=today or dt.datetime.now(UTC).date()
    row=con.execute("""SELECT MIN(checked_at) AS first,MAX(checked_at) AS last,
      COUNT(DISTINCT substr(checked_at,1,10)) AS successful_days,
      COUNT(DISTINCT source_group) AS source_families
      FROM source_checks WHERE status='ok'""").fetchone()
    first=row['first'][:10] if row['first'] else None
    last=row['last'][:10] if row['last'] else None
    completed=0
    if first:
        start=dt.date.fromisoformat(first)+dt.timedelta(days=28)
        end=today-dt.timedelta(days=14)
        cursor=start
        while cursor<=end:
            if _healthy_window(con,cursor):completed+=1
            cursor+=dt.timedelta(days=7)
    return {'status':'ready_to_prepare_unlabelled_snapshots' if completed else 'collect_more_history',
      'first_success':first,'last_success':last,
      'successful_collection_days':row['successful_days'],
      'source_families':row['source_families'],
      'fully_eligible_weekly_snapshots':completed,
      'minimum_window_days':28,'outcome_horizon_days':14,
      'requirements':'At least 28 days of observed collection plus an elapsed 14-day outcome window. Verified outcomes require independent analyst labels.',
      'warning':'The tool cannot infer no incident from no news; labels are never auto-filled.'}
