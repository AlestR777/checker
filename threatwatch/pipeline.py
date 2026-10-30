"""Orchestrates source collection, conservative article matching, classification and scoring."""
from __future__ import annotations
import datetime as dt
import logging
from .config import load_organizations,load_sources
from .entity_graph import runtime_organizations,discover_from_ledger
from .normalize import matching_organizations, classify_rule, CYBER_RE, VULN_RE, HACKTIVIST_RE, UTC, utc_now, key_for_url, parse_date
from .feeds import collect_feeds
from .store import upsert_organizations,add_item,add_discovery
from .scoring import recompute_all
from .ai import AIClassifier

LOG = logging.getLogger(__name__)


def matching_article_organizations(title, summary, organizations):
    """Structured tracker victim names identify an entity, never its brand owner.

    A dealership named 'Lydenburg Toyota' is not Toyota Motor Corporation merely
    because it contains the corporate alias 'Toyota'. General reporting retains
    word-boundary matching; standardized tracker titles require one exact and
    unambiguous canonical name or explicit alias.
    """
    if title.strip().casefold().startswith('ransomware claim:'):
        from .entity_graph import extract_explicit_victim,entity_key
        victim=extract_explicit_victim(title)
        if not victim: return []
        key=entity_key(victim)
        ids=[org.id for org in organizations
             if any(entity_key(alias)==key for alias in (org.name,*org.aliases))]
        return ids if len(ids)==1 else []
    return matching_organizations(title+' '+summary,organizations)


def run_once(con, *, ai: bool = False, ml: bool = False, local_ai: bool = False, local_ai_limit: int = 5, delay: float = 1.25, max_age_days: int = 60,
             organizations=None, sources=None) -> dict:
    orgs = organizations if organizations is not None else load_organizations()
    from .registry import active_sources
    src = sources if sources is not None else active_sources(con)
    upsert_organizations(con,orgs)
    orgs=runtime_organizations(con,orgs)
    classifier = AIClassifier() if ai else None
    text_model = None
    if ml:
        from .text_model import predict
        from .config import ROOT
        text_model = ROOT / 'models' / 'text_model.joblib' 
    start = utc_now()
    run_id = con.execute("INSERT INTO runs (started_at) VALUES (?)", (start,)).lastrowid
    con.commit()
    counts = {"checked":0,"source_failures":0,"fetched":0,"matched":0,"inserted":0,"skipped_undated":0,"catalogued_unmatched":0,"context_items":0,"relinked_mentions":0,"errors":[]}
    # Respect publisher rate limits and avoid hammering repeatedly broken feeds.
    # Source failures never stop healthy sources. HTTPS verification stays enabled.
    previous=con.execute("SELECT source_name,checked_at,error,status FROM source_checks ORDER BY id DESC LIMIT 500").fetchall()
    skip=set(); skip_reason={}; now=dt.datetime.now(UTC);seen=set()
    for r in previous:
        name=r['source_name']
        if name in seen:continue
        seen.add(name)
        if r['status']!='error':continue
        err=(r['error'] or '').lower()
        delay_seconds=(6*3600 if ('429' in err or 'too many requests' in err) else
                       12*3600 if ('403' in err or 'forbidden' in err) else
                       3600 if any(x in err for x in
                         ('unexpected_eof','handshake','timed out','timeout','10054','connection reset')) else 0)
        if not delay_seconds: continue
        try:
            age=(now-dt.datetime.fromisoformat(r['checked_at'])).total_seconds()
            if 0 <= age < delay_seconds:
                skip.add(name);skip_reason[name]=err
        except (TypeError,ValueError):pass
    counts['skipped_rate_limited_sources']=0
    counts['skipped_unavailable_sources']=0
    for name, articles, error in collect_feeds(src, orgs, delay=delay, **({"skip_names":skip} if skip else {})):
        if error and error.startswith('SKIPPED_COOLDOWN:'):
            counts['skipped_rate_limited_sources']+=int('429' in skip_reason.get(name,'') or 'too many requests' in skip_reason.get(name,''))
            counts['skipped_unavailable_sources']+=1
            continue
        counts["checked"] += 1
        # Track healthy collection days, not just evidence events.
        family = ('ransomware-leak-monitors' if name.startswith(('Ransomfeed','RansomLook','Ransomware.live','Ransomwhere')) else
                  'cert.ssi.gouv.fr' if name.startswith('CERT-FR') else
                  'news.google.com' if name.startswith('Google News') else
                  'mastodon-public-social' if name.startswith('Mastodon') else
                  'telegram-public-social' if name.startswith('Telegram') else
                  'vulnerability.circl.lu' if name.startswith('CIRCL') else
                  name.split(' — ')[0].strip().lower())
        con.execute("INSERT INTO source_checks (checked_at,source_name,source_group,status,fetched,error) VALUES (?,?,?,?,?,?)",
                    (utc_now(),name,family,'error' if error else 'ok',len(articles),(error or '')[:500]))
        con.commit()
        counts["fetched"] += len(articles)
        if error:
            counts['source_failures'] += 1
            counts["errors"].append(f"{name}: {error[:130]}")
            continue
        for a in articles:
            # Avoid data pollution from old feeds or unknowable article chronology.
            published_at = parse_date(a.published_at)
            if not published_at:
                counts["skipped_undated"] += 1
                continue
            age = (dt.datetime.now(UTC)-dt.datetime.fromisoformat(published_at)).total_seconds()/86400
            if age < -1 or age > max_age_days:
                continue
            text = a.title+" "+a.summary
            is_cyber = bool(CYBER_RE.search(text) or VULN_RE.search(text))
            is_context = name.startswith('Google News — organization context')
            if not is_cyber and not is_context:
                continue
            ids = matching_article_organizations(a.title,a.summary,orgs)
            if not ids:
                if not is_cyber:
                    continue
                candidate = a.title.partition('Ransomware claim: ')[2].strip() if a.title.startswith('Ransomware claim: ') else ''
                kind, _, _ = classify_rule(a.title,a.summary,a.source_name)
                counts['catalogued_unmatched'] += int(add_discovery(con,url=a.url,title=a.title,summary=a.summary,
                    source_name=a.source_name,source_group=a.source_group,published_at=a.published_at,
                    kind=kind,candidate_name=candidate))
                continue
            counts["matched"] += 1
            # Avoid needless paid AI calls when the item was already collected.
            existing = con.execute("SELECT * FROM items WHERE url_key=?",(key_for_url(a.url),)).fetchone()
            if existing:
                # New watchlist entries/aliases may identify another organization in
                # a previously collected article. Preserve its reviewed classification.
                before = con.total_changes
                add_item(con,url=existing['url'],title=existing['title'],summary=existing['summary'],
                         source_name=existing['source_name'],source_group=existing['source_group'],
                         published_at=existing['published_at'],kind=existing['kind'],
                         confidence=existing['confidence'],rationale=existing['rationale'],org_ids=ids)
                counts['relinked_mentions'] += int(con.total_changes > before)
                continue
            kind,conf,reason = classify_rule(a.title,a.summary,a.source_name)
            if not is_cyber:
                kind,conf,reason = 'context',.45,'Organization-related context, not evidence of a cyberattack'
                counts['context_items'] += 1
            if a.source_group == 'ransomware-leak-monitors':
                kind, conf, reason = 'claim', .85, 'Ransomware tracker listing: unverified actor claim; trackers are not independent corroboration' 
            used_ai = False
            if text_model is not None and is_cyber and a.source_group != 'ransomware-leak-monitors':
                from .text_model import predict
                pred = predict(text_model, (a.title+' '+a.summary)[:6000])
                if pred.get('status')=='predicted_text_label_not_incident_probability' and pred['confidence'] >= .75:
                    kind,conf,reason = pred['label'],min(.80,pred['confidence']), 'Local supervised text triage (not a verified event)'
            if classifier and classifier.enabled and is_cyber and a.source_group != 'ransomware-leak-monitors':
                outcome = classifier.classify(a.title,a.summary,ids)
                if outcome:
                    kind,conf,reason = outcome
                    used_ai = True
            try:
                inserted = add_item(con,url=a.url,title=a.title,summary=a.summary,
                                    source_name=a.source_name,source_group=a.source_group,
                                    published_at=a.published_at,kind=kind,confidence=conf,
                                    rationale=reason,org_ids=ids,ai_used=used_ai)
                counts["inserted"] += int(inserted)
            except Exception as exc:
                counts["errors"].append(f"Item {a.url[:70]}: {str(exc)[:80]}")
    recovery=reconcile_discovery(con,organizations=orgs,limit=5000,recompute=False)
    counts['relinked_from_catalog']=recovery['linked']
    if recovery['errors']:
        counts['errors'].extend(recovery['errors'][:5])
    candidates=discover_from_ledger(con,limit=10000,include_ai=False)
    counts['new_candidate_evidence']=candidates['new_evidence']
    counts['pending_candidates']=candidates['candidate_count']
    from .entity_graph import discover_relation_suggestions
    relation_discovery=discover_relation_suggestions(con,organizations=orgs,limit=5000)
    counts['new_relation_suggestions']=relation_discovery['inserted']
    recompute_all(con,[o.id for o in orgs])
    if local_ai:
        from .local_ai import triage_discovery
        triage=triage_discovery(con,max(1,min(20,local_ai_limit)))
        counts['local_ai_suggestions']=sum(x['status']=='unverified_ai_suggestion' for x in triage)
        counts['local_ai_status']=triage[-1]['status'] if triage else 'no_new_articles'
        extra=discover_from_ledger(con,limit=10000,include_ai=True)
        counts['new_ai_candidate_evidence']=extra['ai_suggestions_used']
    con.execute("""UPDATE runs SET finished_at=?,sources_checked=?,fetched=?,inserted=?,errors=? WHERE id=?""",
                (utc_now(),counts["checked"],counts["fetched"],counts["inserted"],
                 "\n".join(counts["errors"])[:3000],run_id))
    con.commit()
    return counts


def reconcile_discovery(con, *, organizations=None, limit: int = 5000, recompute: bool = True) -> dict:
    """Re-check cached unmatched articles when aliases/watchlist change.

    Evidence stays attributed to the original publisher, with no LLM-generated
    entity link, no re-fetch from target infrastructure and no claim upgrade.
    """
    orgs=organizations if organizations is not None else load_organizations()
    upsert_organizations(con,orgs)
    orgs=runtime_organizations(con,orgs)
    rows=con.execute('SELECT * FROM discovery ORDER BY published_at DESC LIMIT ?',
                     (max(1,min(limit,20000)),)).fetchall()
    result={'checked':len(rows),'linked':0,'unmatched':0,'already_present':0,'errors':[]}
    for row in rows:
        ids=matching_article_organizations(row['title'],row['summary'],orgs)
        if not ids:
            result['unmatched']+=1
            continue
        try:
            existing=con.execute('SELECT * FROM items WHERE url_key=?',(row['url_key'],)).fetchone()
            if existing:
                result['already_present']+=1
                add_item(con,url=existing['url'],title=existing['title'],summary=existing['summary'],
                         source_name=existing['source_name'],source_group=existing['source_group'],
                         published_at=existing['published_at'],kind=existing['kind'],
                         confidence=existing['confidence'],rationale=existing['rationale'],org_ids=ids)
            else:
                kind,conf,reason=classify_rule(row['title'],row['summary'],row['source_name'])
                if row['source_group']=='ransomware-leak-monitors':
                    kind,conf,reason='claim',.75,'Ransomware aggregator claim; independent proof unavailable'
                added=add_item(con,url=row['url'],title=row['title'],summary=row['summary'],
                    source_name=row['source_name'],source_group=row['source_group'],
                    published_at=row['published_at'],kind=kind,confidence=conf,
                    rationale=reason+'; linked from prior unmatched catalog after alias update',org_ids=ids,ai_used=False)
                result['linked']+=int(added)
            con.execute('DELETE FROM discovery WHERE url_key=?',(row['url_key'],))
        except Exception as exc:
            result['errors'].append(f"{row['url'][:70]}: {str(exc)[:100]}")
    con.commit()
    if result['linked'] and recompute:
        recompute_all(con,[o.id for o in orgs])
    return result


def reconcile_mentions(con, *, organizations=None, limit: int = 20000) -> dict:
    """Repair missing entity links in the retained ledger without refetching news.

    This is additive: it never changes human review, source attribution or publication
    dates. New mentions carry today's linked_at, preserving historical cutoffs.
    """
    orgs=organizations if organizations is not None else load_organizations()
    upsert_organizations(con,orgs)
    orgs=runtime_organizations(con,orgs)
    rows=con.execute('SELECT * FROM items ORDER BY id DESC LIMIT ?',
                     (max(1,min(limit,100000)),)).fetchall()
    result={'checked':len(rows),'new_mentions':0}
    for row in rows:
        ids=matching_article_organizations(row['title'],row['summary'],orgs)
        known={r[0] for r in con.execute('SELECT org_id FROM mentions WHERE item_id=?',(row['id'],))}
        missing=[oid for oid in ids if oid not in known]
        if not missing: continue
        add_item(con,url=row['url'],title=row['title'],summary=row['summary'],
                 source_name=row['source_name'],source_group=row['source_group'],
                 published_at=row['published_at'],kind=row['kind'],confidence=row['confidence'],
                 rationale=row['rationale'],org_ids=missing)
        result['new_mentions']+=len(missing)
    result['discovery']=reconcile_discovery(con,organizations=orgs,limit=limit,recompute=False)
    from .entity_graph import discover_relation_suggestions
    result['relations']=discover_relation_suggestions(con,organizations=orgs,limit=limit)
    if result['new_mentions'] or result['discovery']['linked']:
        recompute_all(con,[o.id for o in orgs])
    return result
