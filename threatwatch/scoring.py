"""Eight explainable evidence indicators (0..5 each). NOT compromise probability."""
from __future__ import annotations
import datetime as dt
import json
import math
from collections import Counter
from .normalize import UTC, iso_days_ago, utc_now
from .store import recent_items, save_score

MAX_SCORE = 40
SIGNAL_WEIGHTS = {'claim':1.0, 'threat_statement':1.5, 'incident_report':0.8,
                  'advisory':0.0, 'context':0.0}
DIMENSION_LABELS = {
 'direct_public_threats': 'Публичные заявления об угрозах',
 'unique_claims': 'Число уникальных заявлений',
 'reporting_diversity': 'Разнообразие публикующих источников',
 'signal_velocity': 'Рост сигналов к прошлому окну',
 'freshness': 'Свежесть сообщений',
 'recurrence': 'Повторяемость событий в разные даты',
 'sector_context': 'Контекст активности в отрасли',
 'human_review': 'Независимая ручная проверка публикаций'
}


def _event_identifier(row):
    return str(row['event_id'] or f"item-{row['id']}")


def _usable(row):
    return (row['review_status'] != 'rejected' and row['kind'] in SIGNAL_WEIGHTS
            and SIGNAL_WEIGHTS[row['kind']] > 0 and bool(row['published_at']))


def _sector_context(con, org_id: str, now: dt.datetime, days: int) -> int:
    """Sector activity among other WATCHED organizations, not an unbiased national rate."""
    threshold = (now-dt.timedelta(days=days)).isoformat()
    cnt = con.execute('''SELECT count(DISTINCT c.id) FROM clusters c
       JOIN organizations peer ON peer.id=c.org_id
       JOIN organizations target ON target.sector=peer.sector AND target.id=?
       JOIN cluster_members cm ON cm.cluster_id=c.id JOIN items i ON cm.item_id=i.id
       WHERE c.org_id!=? AND i.published_at>=? AND i.published_at<=?
          AND i.review_status!='rejected' AND c.event_kind IN ('claim','threat_statement','incident_report')''',
       (org_id,org_id,threshold,now.isoformat())).fetchone()[0]
    return min(5,int(cnt))


def compute_score(con, org_id: str, lookback_days: int=14, save: bool=True,
                  *, now: dt.datetime | None=None) -> dict:
    now = now or dt.datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError('now must have timezone')
    start = (now-dt.timedelta(days=2*lookback_days)).isoformat()
    rows = recent_items(con,org_id,start,until=now.isoformat(),limit=10000)
    current, prior = {}, {}
    for row in rows:
        if not _usable(row):
            continue
        when = dt.datetime.fromisoformat(row['published_at'])
        days = (now-when).total_seconds()/86400
        if days < 0 or days > 2*lookback_days:
            continue
        bucket = current if days <= lookback_days else prior
        key = _event_identifier(row)
        bucket.setdefault(key, []).append((row,days))

    current_events = list(current.values())
    prior_events = list(prior.values())
    current_weight = sum(max(SIGNAL_WEIGHTS[x['kind']] * (0.5 if x['review_status']=='disputed' else 1)
                           for x,_ in ev) for ev in current_events)
    prior_weight = sum(max(SIGNAL_WEIGHTS[x['kind']] for x,_ in ev) for ev in prior_events)
    source_groups = {x['source_group'] or x['source_domain'] for ev in current_events for x,_ in ev}
    source_groups.discard('')
    publication_count = sum(len(ev) for ev in current_events)
    direct = len([ev for ev in current_events if any(r['kind']=='threat_statement' for r,_ in ev)])
    explicit_claims = len([ev for ev in current_events if any(r['kind']=='claim' for r,_ in ev)])
    recency_days = min((age for ev in current_events for _,age in ev),default=999)
    event_dates = {ev[0][0]['published_at'][:10] for ev in current_events}
    reviewed = len([ev for ev in current_events if any(r['review_status']=='confirmed' for r,_ in ev)])
    # Review means a human verified the cited publication; NEVER proof of breach.
    dims = {
      'direct_public_threats': min(5,2*direct),
      'unique_claims': min(5,explicit_claims),
      'reporting_diversity': min(5,max(0,len(source_groups)-1)*2),
      'signal_velocity': min(5,math.floor(max(0,current_weight-prior_weight)*1.2)),
      'freshness': 0 if not current_events else (5 if recency_days<=2 else 4 if recency_days<=5 else 3 if recency_days<=9 else 2),
      'recurrence': min(5,max(0,len(event_dates)-1)*2),
      'sector_context': _sector_context(con,org_id,now,lookback_days),
      'human_review': min(5,reviewed*2)
    }
    # Do not infer coverage from high-volume syndicated news coverage.
    # 'coverage' measures quantity/diversity of recorded evidence, not actual recall.
    coverage = min(1.,0.4*min(1,publication_count/4) + .6*min(1,len(source_groups)/3))
    if not current_events:
        status, score = 'insufficient_evidence',None
    elif coverage < 0.34:
        status, score = 'limited_evidence',None
    else:
        status, score = 'monitoring_index_not_probability',sum(dims.values())
    evidence = sorted([{'id':r['id'],'title':r['title'],'url':r['url'],
             'source':r['source_name'],'date':r['published_at'],'kind':r['kind']}
             for ev in current_events for r,_ in ev], key=lambda a:a['date'], reverse=True)[:12]
    result = {'org_id':org_id,'score':score,'score_max':MAX_SCORE,'status':status,
              'coverage':round(coverage,2),'lookback_days':lookback_days,
              'dimensions':dims,'unique_events':len(current_events),
              'counts':{'current_weighted':round(current_weight,2),'prior_weighted':round(prior_weight,2),
                        'independent_sources':len(source_groups), 'current_articles':publication_count},
              'evidence':evidence,
              'disclaimer':'Relative signal index; not a probability, exploitation finding or confirmed attack.'}
    if save:
        save_score(con,org_id,score,result['coverage'],status,json.dumps(result,ensure_ascii=False))
    return result


def recompute_all(con, org_ids: list[str],lookback_days: int=14) -> list[dict]:
    return [compute_score(con,org,lookback_days) for org in org_ids]


def compare_windows(con, org_id: str, boundary: str='2026-10-16',
                    start: str='2026-10-01', end: str='2026-10-29') -> dict:
    rows = recent_items(con,org_id,start+'T00:00:00+00:00',end+'T23:59:59+00:00',limit=10000)
    before=[r for r in rows if r['published_at'] and r['published_at'][:10]<boundary]
    after=[r for r in rows if r['published_at'] and r['published_at'][:10]>=boundary]
    return {'org_id':org_id,'before_count':len(before),'after_count':len(after),
      'before_unique_reported_events':len({_event_identifier(r) for r in before}),
      'after_unique_reported_events':len({_event_identifier(r) for r in after}),
      'before_sources':len({r['source_group'] for r in before}),
      'after_sources':len({r['source_group'] for r in after}),
      'note':'Observations, not attacks. Time windows differ in length; feed availability biases counts.'}


# v6 separates operational priority from confidence and collection health.  The
# legacy eight-dimension score is retained above for historical exports/models.
RISK_MODEL_VERSION = '6.0-priority'
RISK_BASE_POINTS = {'threat_statement': 55., 'incident_report': 35., 'claim': 28.}
RISK_HALF_LIFE_DAYS = {'threat_statement': 7., 'incident_report': 10., 'claim': 7.}


def _risk_date(value):
    """Normalize dates before comparisons; malformed dates never become fresh."""
    from .normalize import parse_date
    parsed = parse_date(value)
    return dt.datetime.fromisoformat(parsed) if parsed else None


def _reporter_patterns(con, org_id):
    """Narrow editorial-role heuristic, not general subject/NER resolution.

    A named security reporter is not automatically the target of the attack it
    describes. Keep all ledger mentions; exclude only explicit reporting roles
    when the same text has no explicit victim/target construction for this org.
    """
    import re
    import unicodedata
    from .config import load_organizations
    from .registry import aliases
    row = con.execute('SELECT name FROM organizations WHERE id=?', (org_id,)).fetchone()
    names = [row['name']] + aliases(con, org_id) if row else []
    try:
        names.extend(alias for org in load_organizations() if org.id == org_id for alias in org.aliases)
    except (OSError,ValueError):
        pass
    normalized = {unicodedata.normalize('NFKC', name).casefold().strip() for name in names}
    escaped = [re.escape(name) for name in sorted(normalized,key=len,reverse=True) if len(name)>=3]
    if not escaped:
        return None
    org = r'(?<!\w)(?:' + '|'.join(escaped) + r')(?!\w)'
    reporter = re.compile(
        org + r"(?:['’]s)?\s+(?:(?:security\s+)?(?:researchers?|analysts?|experts?|security team)\s+"
        r"(?:warn\w*|report\w*|say\w*|find\w*|found|discover\w*|detect\w*|reveal\w*)\b"
        r"|warns?\b)"
        r'|(?:according to(?:\s+(?:researchers|analysts|experts)\s+at)?|по данным|'
        r'исследователи|аналитики|эксперты|специалисты)\s+(?:компании\s+)?' + org)
    victim = re.compile(
        org + r"(?:['’]s)?\s+(?:(?:(?:is|was|has been|had been)\s+)?"
        r"(?:hit|attacked|breached|targeted|compromised|suffered)\b"
        r"|(?:confirms?|discloses?|acknowledges?)\s+(?:(?:a|an|its|own)\s+)*"
        r"(?:data breach|cyberattack|cyber attack|ransomware attack|security incident|breach)\b"
        r"|(?:подтвердил\w*|пострадал\w*|подверг\w*)\s+(?:от\s+|свою\s+)?"
        r"(?:утеч\w*|атак\w*|взлом\w*|кибератак\w*))"
        r'|(?:attacks?\s+(?:on|against)|breach\s+at|targets?|targeting|'
        r'атак\w*\s+на|взлом\w*\s+|утеч\w*\s+(?:в|из))\s*' + org)
    return reporter, victim


def _risk_events(con, org_id, now, days, include_synthetic=False):
    import re
    import unicodedata
    def title_tokens(text):
        return frozenset(re.findall(r'\w{3,}', unicodedata.normalize('NFKC', text).casefold()))
    # Read raw rows, not a SQL string-date window: offsets and Z are equivalent.
    # Older rows still establish an identical story's original publication date;
    # limiting this scan to the window would turn old reposts into new events.
    rows = con.execute('''SELECT i.*, m.linked_at FROM items i
        JOIN mentions m ON m.item_id=i.id WHERE m.org_id=?
        ORDER BY i.published_at DESC, i.id''', (org_id,))
    usable, ignored = [], {'synthetic': 0, 'undated': 0, 'rejected': 0, 'reporter_context': 0}
    oldest_identical = {}
    roles = _reporter_patterns(con,org_id)
    for raw in rows:
        row = dict(raw)
        if row['origin'] == 'synthetic' and not include_synthetic:
            ignored['synthetic'] += 1
            continue
        if row['review_status'] == 'rejected':
            ignored['rejected'] += 1
            continue
        published = _risk_date(row['published_at'])
        if not published:
            ignored['undated'] += 1
            continue
        age = (now - published).total_seconds() / 86400
        # A historical assessment must not use evidence ingested or linked later.
        observed = _risk_date(row['collected_at'])
        linked = _risk_date(row['linked_at'])
        if age < 0 or (observed and observed > now) or (linked and linked > now):
            continue
        if row['kind'] not in RISK_BASE_POINTS:
            continue
        if roles:
            text = unicodedata.normalize('NFKC',row['title'] + '. ' + row['summary']).casefold()
            if roles[0].search(text) and not roles[1].search(text):
                if age <= days:
                    ignored['reporter_context'] += 1
                continue
        tokens = title_tokens(row['title'])
        oldest_identical[tokens] = min(published, oldest_identical.get(tokens, published))
        if age > days:
            continue
        review_factor = .5 if row['review_status'] == 'disputed' else 1.
        row['age_days'] = round(age, 3)
        row['_published'] = published
        # A classifier's confidence is not source reliability and cannot be used
        # as the probability of an attack. Human confirmation adds no risk points.
        row['_strength'] = (RISK_BASE_POINTS[row['kind']] * review_factor *
                            2 ** (-age / RISK_HALF_LIFE_DAYS[row['kind']]))
        usable.append(row)
    # Cross-publisher and cross-kind repetitions of the same story count once.
    # Avoid ASCII-only similarity collapsing all Cyrillic headlines to nothing.
    events = []
    for row in sorted(usable, key=lambda r: (r['_published'], r['id'])):
        tokens = title_tokens(row['title'])
        event = None
        for candidate in reversed(events):
            anchor = candidate[0]
            other = title_tokens(anchor['title'])
            overlap = len(tokens & other) / max(1, len(tokens | other))
            near = abs((row['_published'] - anchor['_published']).total_seconds()) <= 2 * 86400
            if tokens == other or (near and overlap >= .8):
                event = candidate
                break
        if event is None:
            events.append([row])
        else:
            event.append(row)
    current_events = []
    for event in events:
        # The oldest publication anchors the event. Republishing an identical
        # claim must not reset its clock and manufacture a fresh threat.
        anchor = min(oldest_identical[title_tokens(r['title'])] for r in event)
        age = (now - anchor).total_seconds() / 86400
        if age > days:
            continue
        for row in event:
            row['_strength'] = (RISK_BASE_POINTS[row['kind']] *
                (.5 if row['review_status']=='disputed' else 1.) *
                2 ** (-age / RISK_HALF_LIFE_DAYS[row['kind']]))
        current_events.append(event)
    return current_events, ignored


def _direct_priority(events):
    strengths = sorted((max(r['_strength'] for r in event) for event in events), reverse=True)
    # Correlated reporting cannot grow a score without bound. Subsequent unique
    # events add diminishing context; one event never gets a source-count bonus.
    return min(75., sum(value * (.45 ** index) for index, value in enumerate(strengths)))


def _collection_health(con, now):
    rows = con.execute('''SELECT s.* FROM source_checks s WHERE s.id=(
        SELECT s2.id FROM source_checks s2 WHERE s2.source_name=s.source_name
        AND s2.checked_at<=? ORDER BY s2.checked_at DESC,s2.id DESC LIMIT 1)''',
        (now.isoformat(),)).fetchall()
    checks = [(dict(r), _risk_date(r['checked_at'])) for r in rows]
    checks = [(r, when) for r, when in checks if when and when <= now]
    latest = max((when for _, when in checks), default=None)
    recent = [r for r, when in checks if now - when <= dt.timedelta(hours=24)]
    ok = sum(r['status'] == 'ok' for r in recent)
    error = sum(r['status'] == 'error' for r in recent)
    status = ('never_run' if not latest else 'stale' if not recent else
              'partial' if error or len(recent) < len(checks) else 'healthy')
    return {'latest_source_check': latest.isoformat() if latest else None,
            'sources_ok': ok, 'sources_error': error, 'sources_stale': len(checks)-len(recent),
            'collection_status': status}


def assess_risk(con, org_id: str, lookback_days: int = 30, *,
                now: dt.datetime | None = None, include_synthetic: bool = False,
                _cache: dict | None = None) -> dict:
    """Explainable 0–100 monitoring priority, never a breach probability.

    Direct evidence (max 75), verified relationship context (max 15) and peer
    activity (max 10) are shown independently. This is a heuristic policy, not a
    validated prediction. Missing signals and broken collection remain unknown.
    The call is read-only and does not overwrite legacy score history.
    """
    now = now or dt.datetime.now(UTC)
    if now.tzinfo is None:
        raise ValueError('now must have timezone')
    now = now.astimezone(UTC)
    if not isinstance(lookback_days, int) or not 1 <= lookback_days <= 365:
        raise ValueError('lookback_days must be between 1 and 365')
    org = con.execute('SELECT * FROM organizations WHERE id=?', (org_id,)).fetchone()
    if not org:
        raise ValueError('Unknown organization')
    cache = _cache if _cache is not None else {}
    def events_for(oid):
        if oid not in cache:
            cache[oid] = _risk_events(con, oid, now, lookback_days, include_synthetic)
        return cache[oid][0]
    events = events_for(org_id)
    ignored = cache[org_id][1]
    direct = _direct_priority(events)
    relations = con.execute('''SELECT r.*,o.name AS other_name,
        CASE WHEN r.source_org_id=? THEN r.target_org_id ELSE r.source_org_id END AS other_id
        FROM organization_relations r JOIN organizations o ON o.id=CASE
        WHEN r.source_org_id=? THEN r.target_org_id ELSE r.source_org_id END
        WHERE (r.source_org_id=? OR r.target_org_id=?) AND r.source_org_id!=r.target_org_id''',
        (org_id,org_id,org_id,org_id)).fetchall()
    eligible_types = {'parent','subsidiary','supplier','customer','partner','agency','same_group','other_documented'}
    affected, verified, unverified = {}, set(), set()
    for r in relations:
        observed = _risk_date(r['recorded_at'])
        verified_at = _risk_date(r['verified_at'])
        if observed and observed > now:
            continue
        oid = r['other_id']
        if r['review_status'] != 'verified' or not verified_at or verified_at > now:
            unverified.add(oid)
            continue
        verified.add(oid)
        if r['relation_type'] not in eligible_types or not r['evidence_url'].startswith('https://'):
            continue
        strength = _direct_priority(events_for(oid))
        if strength:
            # One neighbor contributes once even with duplicate citations/edges.
            affected.setdefault(oid, {'org_id':oid,'name':r['other_name'],
                'relation_type':r['relation_type'],'evidence_url':r['evidence_url'],
                'direct_score':round(strength,1)})
    related = min(15., sum(min(8., p['direct_score'] * .15) for p in affected.values()))
    # Same sector is shared context, never an invented corporate relationship.
    sector_peers = []
    if org['sector'].strip().casefold() not in {'','unknown','other','неизвестно'}:
        for peer in con.execute('SELECT id,name FROM organizations WHERE sector=? AND id!=?',
                                (org['sector'],org_id)):
            if peer['id'] in affected:
                continue  # Do not double-count a related affected organization.
            strength = _direct_priority(events_for(peer['id']))
            if strength:
                sector_peers.append({'org_id':peer['id'],'name':peer['name'],
                                     'direct_score':round(strength,1)})
    sector = min(10., sum(min(3.,p['direct_score']*.06) for p in sector_peers))
    total = round(direct + related + sector)
    score = max(1,total) if events or related or sector else None
    status = 'scored' if events else 'context_only' if score is not None else 'no_signals'
    level = ('unknown' if score is None else 'critical' if score>=75 else
             'high' if score>=50 else 'elevated' if score>=25 else 'low')
    all_rows = [row for event in events for row in event]
    sources = {r['source_group'] or r['source_domain'] for r in all_rows}
    sources.discard('')
    review_count = sum(any(r['review_status']=='confirmed' for r in ev) for ev in events)
    confidence_level = ('none' if not events else 'high' if len(sources)>=3 and review_count>=2
                        else 'medium' if len(sources)>=2 or review_count else 'low')
    kinds = Counter(max(event,key=lambda r:r['_strength'])['kind'] for event in events)
    evidence = []
    remaining_tenths = round(direct * 10)
    for index,event in enumerate(sorted(events,key=lambda ev:max(r['_strength'] for r in ev),reverse=True)):
        representative = max(event,key=lambda r:r['_strength'])
        event_date = min(r['_published'] for r in event)
        # Attribute only points actually included in the capped direct score.
        # Integer tenths keep displayed contributions within the displayed cap.
        contribution_tenths = min(remaining_tenths,
            round(representative['_strength'] * (.45 ** index) * 10))
        remaining_tenths -= contribution_tenths
        evidence.append({'id':representative['id'],'title':representative['title'],
            'url':representative['url'],'source':representative['source_name'],
            'date':representative['published_at'],'kind':representative['kind'],
            'age_days':representative['age_days'],'review_status':representative['review_status'],
            'event_id':f"risk-{min(r['id'] for r in event)}",'publications':len(event),
            'event_date':event_date.isoformat(),
            'event_age_days':round((now-event_date).total_seconds()/86400,3),
            'contribution':contribution_tenths / 10,
            'synthetic':representative['origin']=='synthetic'})
    return {'org_id':org_id,'score':score,'score_max':100,'status':status,'level':level,
        'direct_score':round(direct,1),'related_score':round(related,1),'sector_score':round(sector,1),
        'components':[
            {'id':'direct','label':'Прямые сигналы','points':round(direct,1),'max_points':75,
             'explanation':'Угрозы: 55, сообщения об инцидентах: 35, заявления: 28. Полураспад за 7–10 дней; повторы одной новости не добавляют баллы. Явная роль исследователя или источника сообщения исключается узкой эвристикой, если нет прямого указания на эту организацию как цель.'},
            {'id':'related','label':'Подтверждённые связи','points':round(related,1),'max_points':15,
             'explanation':'Ограниченный контекст сигналов у документально связанных организаций. Не означает переход атаки.'},
            {'id':'sector','label':'Отраслевой фон','points':round(sector,1),'max_points':10,
             'explanation':'Сигналы у других наблюдаемых организаций отрасли. Это контекст, а не доказательство связи или уязвимости.'}],
        'counts':{'events':len(events),'articles':len(all_rows),'source_groups':len(sources),
                  'threats':kinds['threat_statement'],'claims':kinds['claim'],'incidents':kinds['incident_report'],
                  'reviewed_events':review_count},
        'evidence':evidence[:20],
        'confidence':{'level':confidence_level,
            'explanation':'Оценка объёма и проверки собранных свидетельств; не вероятность и не полнота охвата. Число источников и ручная проверка не повышают риск.'},
        'data_health':_collection_health(con,now),
        'relationships':{'verified':len(verified),'unverified':len(unverified),
                         'affected_peers':list(affected.values()),'sector_peers':sector_peers[:20]},
        'ignored':ignored,
        'ignored_explanation':'Публикации и упоминания сохранены. reporter_context: явная роль исследователя или источника сообщения; эвристика не гарантирует точность определения роли.',
        'lookback_days':lookback_days,'computed_at':now.isoformat(),
        'model_version':RISK_MODEL_VERSION,
        'disclaimer':'Индекс приоритета мониторинга, а не вероятность будущего взлома. Калиброванного прогноза без размеченной истории нет.'}


def assess_all(con, org_ids=None, lookback_days=30, *, now=None, include_synthetic=False):
    """Assess the active registry using one timestamp and shared evidence cache."""
    now = now or dt.datetime.now(UTC)
    if org_ids is None:
        org_ids = [r[0] for r in con.execute('''SELECT o.id FROM organizations o
            LEFT JOIN organization_preferences p ON p.org_id=o.id
            WHERE COALESCE(p.active,1)=1 ORDER BY o.name''')]
    cache = {}
    return [assess_risk(con,oid,lookback_days,now=now,include_synthetic=include_synthetic,
                        _cache=cache) for oid in org_ids]
