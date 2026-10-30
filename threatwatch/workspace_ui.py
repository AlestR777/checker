"""Server-rendered analyst workspace. No CDN, browser scripts or frontend build."""
from __future__ import annotations
import html
import json
from urllib.parse import urlencode, quote, urlsplit

LEVELS = {'unknown':'Нет сигналов','low':'Низкий','elevated':'Повышенный','high':'Высокий','critical':'Критический'}
CONFIDENCE = {'none':'Нет прямых данных','low':'Ограниченные данные','medium':'Средняя опора на данные','high':'Хорошая опора на данные'}
KINDS = {'claim':'Заявление','threat_statement':'Прямая угроза','incident_report':'Сообщение об инциденте','advisory':'Бюллетень','context':'Контекст'}
REVIEWS = {'unreviewed':'Не проверено','confirmed':'Публикация проверена','disputed':'Оспаривается','rejected':'Отклонено'}
RELATIONS = {'parent':'Материнская компания','subsidiary':'Дочерняя компания','supplier':'Поставщик','customer':'Клиент','partner':'Партнёр','agency':'Ведомственная связь','same_group':'Одна группа','other_documented':'Документированная связь'}
SECTORS = {'telecom':'Телеком','public_administration':'Госсектор','retail':'Ритейл','energy':'Энергетика','manufacturing':'Промышленность','transport':'Транспорт','maritime':'Морская отрасль','political_party':'Политическая организация','healthcare':'Медицина','finance':'Финансы','technology':'Технологии','education':'Образование'}

def esc(value):
    return html.escape(str(value if value is not None else ''), quote=True)


def org_url(oid):
    return '/org/'+quote(str(oid),safe='')


def href(url):
    try:
        parsed=urlsplit(str(url))
        return esc(url) if parsed.scheme in {'https','http'} and parsed.hostname and not parsed.username else '#'
    except ValueError:
        return '#'


def initials(name):
    parts=str(name).split()
    return esc(''.join(p[0] for p in parts[:2]).upper())


def sector(name):
    return SECTORS.get(name,name or 'Отрасль не указана')



def relation_label(edge, focal_id):
    kind = edge['relation_type']
    if edge.get('source_org_id') and edge['source_org_id'] != focal_id:
        kind = {'parent':'subsidiary','subsidiary':'parent','supplier':'customer','customer':'supplier'}.get(kind,kind)
    return RELATIONS.get(kind,kind)


def shell(title, body, css):
    from .runtime import runtime_info
    running_version=runtime_info()['version']
    nav=[('Обзор','/','◈'),('Инциденты','/incidents','≋'),('Организации','/organizations','▦'),('Граф связей','/graph','⌘'),('Источники','/sources','◉')]
    links=''.join(f'<a href="{url}"'+(' class="active" aria-current="page"' if title==label or (label=='Граф связей' and title=='Граф связей') else '')+f'><span class="nav-icon" aria-hidden="true">{icon}</span>{label}</a>' for label,url,icon in nav)
    return f'''<!DOCTYPE html><html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#09090d"><title>{esc(title)} · ThreatWatch</title><style>{css}</style></head><body>
    <aside class="sidebar"><a class="brand" href="/"><span class="brandmark" aria-hidden="true">◈</span>ThreatWatch</a><div class="brand-sub">Intelligence workspace</div><div class="nav-label">Мониторинг</div><nav aria-label="Основная навигация">{links}<div class="nav-label">Аналитика и контроль</div><a href="/candidates"><span class="nav-icon" aria-hidden="true">⊕</span>Очередь проверки</a><a href="/analytics"><span class="nav-icon" aria-hidden="true">▥</span>Статистика</a><a href="/control"><span class="nav-icon" aria-hidden="true">≡</span>Управление сбором</a><details><summary>Исследования и данные</summary><div><a href="/discovery">Каталог публикаций</a><a href="/events">Журнал событий</a><a href="/audit">Аудит распознавания</a><a href="/quality">Качество данных</a><a href="/research">Историческая модель</a><a href="/cybermap">Cybermap</a><a href="/method">Методология оценки</a><a href="/api/risks">JSON API</a></div></details></nav><div class="sidebar-foot">Публичные источники<br><span style="color:#d2c8df">Глобальный мониторинг</span><br><a href="/method">Модель риска · v6</a></div></aside>
    <div class="app-shell"><header class="topbar"><div class="breadcrumb">Рабочее пространство <span aria-hidden="true"> / </span> <b>{esc(title)}</b></div><div class="workspace-label">OSINT · THREAT INTELLIGENCE</div><a class="tag info" href="/about" aria-label="О приложении, версия {esc(running_version)}" style="flex-shrink:0">ThreatWatch v{esc(running_version)}</a></header><main class="wrap">{body}</main><footer class="wrap">ThreatWatch · Индекс приоритета мониторинга 0–100. Не является вероятностью будущего взлома. Открытые сообщения требуют проверки.</footer></div></body></html>'''.encode('utf-8')


def risk_badge(risk):
    label='Только контекст' if risk['status']=='context_only' else LEVELS[risk['level']]
    return f'<span class="tag {risk["level"]}">{label}</span>'


def risk_number(risk):
    value=risk['score']
    if value is None:
        return '<span class="score muted">—</span><div class="org-meta">Недостаточно данных</div>'
    return f'<span class="score">{value}<small> / 100</small></span><div class="score-track {risk["level"]}"><span style="width:{value}%"></span></div>'


def collection_status(health):
    state=health['collection_status']
    labels={'never_run':'Сбор ещё не запускался','stale':'Данные сбора устарели','partial':'Есть ошибки источников','healthy':'Последние проверки источников успешны'}
    cls='unknown' if state=='never_run' else 'warning' if state in {'stale','partial'} else ''
    return f'<span class="health-line"><span class="health-dot {cls}"></span>{labels.get(state,state)}</span>'


def overview(con, query):
    from .scoring import assess_all
    orgs={r['id']:dict(r) for r in con.execute('SELECT * FROM organizations')}
    risks=assess_all(con)
    by_org={r['org_id']:r for r in risks}
    country=(query.get('country') or [''])[0][:60]
    selected_sector=(query.get('sector') or [''])[0][:100]
    level=(query.get('level') or [''])[0][:30]
    search=(query.get('q') or [''])[0][:150].strip()
    # Retain old bookmarked status filters while moving the UI to the new model.
    legacy_status=(query.get('status') or [''])[0]
    rows=[]
    for risk in risks:
        org=orgs[risk['org_id']]
        if country and org['country']!=country:continue
        if selected_sector and org['sector']!=selected_sector:continue
        if level and not (risk['level']==level or level=='high' and risk['level']=='critical'):continue
        if search and search.casefold() not in (org['name']+' '+org['id']).casefold():continue
        if legacy_status=='insufficient_evidence' and risk['score'] is not None:continue
        rows.append((org,risk))
    rows.sort(key=lambda pair:(-(pair[1]['score'] if pair[1]['score'] is not None else -1),pair[0]['name'].casefold()))
    total_filtered=len(rows)
    page_size=15
    total_pages=max(1,(total_filtered+page_size-1)//page_size)
    try: current_page=max(1,min(int((query.get('page') or ['1'])[0]),total_pages))
    except (ValueError,TypeError): current_page=1
    rows=rows[(current_page-1)*page_size:current_page*page_size]
    page_params={key:values[0] for key,values in query.items() if key in {'q','country','sector','level','status'} and values and values[0]}
    def page_link(number,label):
        params=dict(page_params,page=number)
        return f'<a href="/?{esc(urlencode(params))}">{label}</a>'
    pagination=(page_link(current_page-1,'← Назад')+' · ' if current_page>1 else '')+f'Страница {current_page} из {total_pages}'+(' · '+page_link(current_page+1,'Далее →') if current_page<total_pages else '')
    countries=sorted({orgs[r['org_id']]['country'] for r in risks if orgs[r['org_id']]['country']})
    sectors=sorted({orgs[r['org_id']]['sector'] for r in risks if orgs[r['org_id']]['sector']})
    def options(values,current,empty,labels=None):
        return '<option value="">'+empty+'</option>'+''.join(f'<option value="{esc(v)}"'+(' selected' if current==v else '')+f'>{esc((labels or {}).get(v,v))}</option>' for v in values)
    pending=con.execute("SELECT count(*) FROM entity_candidates WHERE status='pending'").fetchone()[0]
    relations=con.execute("SELECT count(*) FROM organization_relations WHERE review_status='verified'").fetchone()[0]
    high=sum(r['level'] in {'high','critical'} for r in risks)
    unknown=sum(r['score'] is None for r in risks)
    health=risks[0]['data_health'] if risks else {'collection_status':'never_run','sources_ok':0,'sources_error':0,'latest_source_check':None}
    table=''
    for org,risk in rows:
        ties=risk['relationships']['verified']
        tie_label=f'{ties} провер.' if ties else 'Нет проверенных'
        table+=f'''<tr><td><a class="org-link" href="{org_url(org['id'])}"><span class="org-avatar" aria-hidden="true">{initials(org['name'])}</span><span><strong>{esc(org['name'])}</strong><div class="org-meta">{esc(org['country'])} · {esc(sector(org['sector']))}</div></span></a></td><td>{risk_number(risk)}</td><td>{risk_badge(risk)}<div class="org-meta">{CONFIDENCE[risk['confidence']['level']]}</div></td><td><a href="/graph?{esc(urlencode({'org_id':org['id']}))}">{tie_label}</a><div class="org-meta">{risk['relationships']['unverified']} требуют проверки</div></td><td>{risk['counts']['events']}<div class="org-meta">уникальных событий</div></td></tr>'''
    if not table:
        table='<tr><td colspan="5"><div class="empty-state"><div class="empty-icon">⌕</div><h3>Нет организаций с такими фильтрами</h3><p>Измените запрос или сбросьте фильтры.</p><a href="/" class="button secondary">Сбросить фильтры</a></div></td></tr>'
    signals=con.execute('''SELECT DISTINCT i.* FROM items i JOIN mentions m ON m.item_id=i.id
        LEFT JOIN organization_preferences p ON p.org_id=m.org_id
        WHERE COALESCE(p.active,1)=1 AND i.review_status!='rejected'
        ORDER BY i.published_at DESC LIMIT 6''').fetchall()
    news=''
    for item in signals:
        demo=' <span class="tag unknown">DEMO</span>' if item['origin']=='synthetic' else ''
        news+=f'''<article class="signal-item"><div class="signal-meta"><span class="tag info">{esc(KINDS.get(item['kind'],item['kind']))}</span>{esc((item['published_at'] or '')[:10])}{demo}</div><a class="signal-title" href="{href(item['url'])}" target="_blank" rel="noopener noreferrer">{esc(item['title'])} →</a><div class="signal-source">{esc(item['source_name'])} · {esc(REVIEWS.get(item['review_status'],item['review_status']))}</div></article>'''
    if not news:
        news='''<div class="empty-state"><div class="empty-icon">≋</div><h3>Лента пока пуста</h3><p>Запустите сбор из открытых источников. Новости появятся здесь после сопоставления с организациями.</p><a class="button secondary" href="/control">Начать сбор</a></div>'''
    preserving={k:v[0] for k,v in query.items() if k in {'q','country','sector'} and v and v[0]}
    def tab(value,label):
        params=dict(preserving)
        if value:params['level']=value
        target='/?'+urlencode(params) if params else '/'
        return f'<a href="{esc(target)}"'+(' class="current"' if level==value else '')+f'>{label}</a>'
    last=(health.get('latest_source_check') or '')[:16].replace('T',' ') or 'нет проверок'
    onboarding=''
    if not con.execute('SELECT 1 FROM items LIMIT 1').fetchone():
        onboarding='''<section class="card intro-panel" aria-labelledby="first-run-title" style="margin-bottom:24px"><div class="section-head"><h2 id="first-run-title">Новая рабочая панель ThreatWatch 6</h2><span class="tag info">Начните здесь</span></div><p class="lead">Индекс 0–100 с объяснением каждого вклада, проверяемые связи и отдельная оценка качества данных. Сейчас публикаций в базе нет — вместо выдуманных баллов показаны прочерки.</p><div style="display:flex;flex-wrap:wrap;gap:24px;margin-top:18px"><div style="flex:1;min-width:180px"><h3><span class="accent-purple">01</span> · Выберите организации</h3><p class="panel-subtitle" style="margin:0">Добавьте компании и варианты названий.<br><a href="/organizations">Открыть справочник →</a></p></div><div style="flex:1;min-width:180px"><h3><span class="accent-purple">02</span> · Соберите новости</h3><p class="panel-subtitle" style="margin:0">Открытые источники заполнят ленту сигналов.<br><a href="/control">Сбор и расписание →</a></p></div><div style="flex:1;min-width:180px"><h3><span class="accent-purple">03</span> · Проверьте связи</h3><p class="panel-subtitle" style="margin:0">Отношения сохраняют источник и статус проверки.<br><a href="/graph">Перейти к графу →</a></p></div></div></section>'''
    return f'''<div class="page-heading overview-heading"><div><p class="eyebrow eyebrow-pill">Глобальный мониторинг · 30 дней</p><h1>Сигналы сегодня.<br><span class="hero-accent">Риски — в фокусе.</span></h1><p class="lead">Публичные сигналы, организации и их связи. Понимайте, что изменилось и куда направить внимание.</p></div><div class="button-row"><a class="button quiet" href="/export/risks">↓ Экспорт</a><a class="button" href="/control">Обновить данные →</a></div></div>
    {onboarding}<div class="metrics"><div class="card"><div class="metric-label">Организаций в мониторинге <span class="metric-symbol">▦</span></div><div class="metric">{len(risks)}</div><div class="metric-caption">{unknown} без достаточных сигналов</div></div><div class="card"><div class="metric-label">Высокий приоритет <span class="metric-symbol">→</span></div><div class="metric accent-rose">{high}</div><div class="metric-caption">Индекс от 50 · требует внимания</div></div><div class="card"><div class="metric-label">Проверенных связей <span class="metric-symbol">⌘</span></div><div class="metric accent-purple">{relations}</div><div class="metric-caption">Отношения с указанным источником</div></div><div class="card"><div class="metric-label">Ожидают проверки <span class="metric-symbol">⊕</span></div><div class="metric accent-amber">{pending}</div><div class="metric-caption"><a href="/candidates">Новые организации →</a></div></div></div>
    <div class="dashboard-grid"><section class="card table-card"><div class="section-head"><h2>Организации <span class="count-label">{total_filtered} из {len(risks)}</span></h2><a href="/organizations" style="font-size:11px">Управление →</a></div><div class="tabs">{tab('','Все организации')}{tab('high','Высокий приоритет')}{tab('unknown','Без сигналов')}</div><form class="filters" method="get" action="/"><label class="filter-label" for="org-search">Поиск организации</label><input id="org-search" name="q" type="search" placeholder="Поиск организации…" value="{esc(search)}"><label class="filter-label" for="filter-country">Страна</label><select id="filter-country" name="country">{options(countries,country,'Все страны')}</select><label class="filter-label" for="filter-sector">Отрасль</label><select id="filter-sector" name="sector">{options(sectors,selected_sector,'Все отрасли',SECTORS)}</select><label class="filter-label" for="filter-level">Приоритет</label><select id="filter-level" name="level">{options(LEVELS,level,'Любой приоритет',LEVELS)}</select><button type="submit">Найти</button></form><div class="table-scroll"><table><thead><tr><th>Организация</th><th>Индекс</th><th>Приоритет / данные</th><th>Связи</th><th>За 30 дней</th></tr></thead><tbody>{table}</tbody></table></div><div class="table-footer"><span>Показано {len(rows)} из {total_filtered} · индекс ↓</span><span>{pagination}</span></div></section><aside class="card"><div class="section-head"><h2>Последние сигналы</h2><a href="/incidents" style="font-size:11px">Все →</a></div><p class="panel-subtitle">Публичные сообщения по организациям</p>{news}</aside></div>
    <div class="monitor-note"><div>{collection_status(health)}<p style="margin-top:5px">Проверка: {esc(last)} UTC · успешных источников: {health['sources_ok']} · ошибок: {health['sources_error']}</p></div><a class="button secondary" href="/sources">Проверить источники</a></div><div class="note"><b>Как читать индекс.</b> Приоритет основан на свежих сигналах и проверяемых связях. Он помогает выбрать, что изучить первым. Отсутствие публикаций означает недостаток данных; оценка не является вероятностью будущего взлома. <a href="/method">Методология →</a></div>'''


def organization_detail(con, org_id):
    from .scoring import assess_risk
    from .store import recent_items
    from .briefs import local_brief, brief_fingerprint
    from .entity_graph import organization_connections
    org=con.execute('SELECT * FROM organizations WHERE id=?',(org_id,)).fetchone()
    if not org:return None
    risk=assess_risk(con,org_id)
    rel=organization_connections(con,org_id,limit=30)
    brief=local_brief(con,org_id)
    if risk.get('ignored',{}).get('reporter_context'):
        brief=dict(brief)
        brief['text']=(f"В сохранённых публикациях организация явно выступает источником предупреждения или исследования "
                       f"({risk['ignored']['reporter_context']} сообщений), поэтому эти упоминания не прибавляют прямые баллы. "
                       "Материалы остаются ниже для проверки. Это ограниченная эвристика; роли организаций в остальных новостях требуют проверки.")
    cached=con.execute('SELECT text,created_at,fingerprint FROM org_briefs WHERE org_id=?',(org_id,)).fetchone()
    ai=''
    if cached and cached['fingerprint']==brief_fingerprint(brief):
        ai=f'<details><summary>Дополнительная ИИ-выжимка · требует проверки</summary><p>{esc(cached["text"])}</p><small>{esc(cached["created_at"])}</small></details>'
    components=''
    for component in risk['components']:
        width=round(component['points']/component['max_points']*100,1)
        components+=f'''<div class="component"><div class="component-title"><span>{esc(component['label'])}</span><span>{component['points']:g} <small>/ {component['max_points']}</small></span></div><div class="bar"><span style="width:{width}%"></span></div><p>{esc(component['explanation'])}</p></div>'''
    value='—' if risk['score'] is None else risk['score']
    angle=(risk['score'] or 0)*3.6
    color={'unknown':'#776582','low':'#b68aef','elevated':'#d5b383','high':'#d69ab5','critical':'#d69ab5'}[risk['level']]
    publications=''
    for item in recent_items(con,org_id,limit=100):
        demo=' <span class="tag unknown">DEMO</span>' if item['origin']=='synthetic' else ''
        publications+=f'''<article class="signal-item"><div class="signal-meta"><span class="tag info">{esc(KINDS.get(item['kind'],item['kind']))}</span>{esc((item['published_at'] or 'Дата не указана')[:10])} · {esc(REVIEWS.get(item['review_status'],item['review_status']))}{demo}</div><a class="signal-title" href="{href(item['url'])}" target="_blank" rel="noopener noreferrer">{esc(item['title'])} →</a><div class="signal-source">{esc(item['source_name'])} · {esc(item['rationale'])}</div></article>'''
    if not publications:
        publications='<div class="empty-state"><div class="empty-icon">≋</div><h3>Публикаций пока нет</h3><p>Это не подтверждает низкий риск. Проверьте варианты названия организации и доступность источников.</p><a class="button secondary" href="/control">Обновить данные</a></div>'
    connections=''
    for edge in rel['documented']:
        reviewed=edge['review_status']=='verified'
        excerpt=f'<small>{esc(edge.get("evidence_excerpt", ""))}</small>' if edge.get('evidence_excerpt') else ''
        connections+=f'''<div class="connection-item"><span class="org-avatar" aria-hidden="true">{initials(edge['other_name'])}</span><div class="connection-info"><a href="{org_url(edge['other_id'])}">{esc(edge['other_name'])}</a><small>{esc(relation_label(edge,org_id))}</small>{excerpt}<small><a href="{href(edge['evidence_url'])}" target="_blank" rel="noopener noreferrer">Первоисточник →</a></small></div><span class="tag {'low' if reviewed else 'unknown'}">{'Проверена' if reviewed else 'Проверить'}</span></div>'''
    if not connections:
        connections='<p class="empty-inline">Документированных связей пока нет. Добавьте отношение с первоисточником или проверьте предложения обогащения.</p>'
    pending=''
    for edge in rel.get('pending',[]):
        name=edge.get('other_name') or edge.get('target_name') or edge.get('name') or edge.get('candidate_name') or 'Организация'
        cid=edge.get('target_candidate_id') or edge.get('candidate_id')
        link=f'/candidate/{int(cid)}' if cid else '/candidates'
        pending+=f'<div class="connection-item"><div class="connection-info"><a href="{link}">{esc(name)}</a><small>{esc(RELATIONS.get(edge.get("relation_type"),edge.get("relation_type","Предложение")))}</small><small><a href="{href(edge.get("evidence_url", ""))}">Источник →</a></small></div><span class="tag unknown">Кандидат</span></div>'
    if pending:connections+='<h3 style="margin-top:20px">Связанные кандидаты</h3><p class="panel-subtitle">Сначала проверьте организацию, затем само отношение</p>'+pending
    co=''.join(f'<div class="connection-item"><div class="connection-info"><a href="{org_url(e["id"])}">{esc(e["name"])}</a><small>{e["articles"]} общих публикаций · <a href="{href(e["example_url"])}">пример →</a></small></div></div>' for e in rel['co_mentioned'])
    peers=''.join(f'<div class="connection-item"><div class="connection-info"><a href="{org_url(e["id"])}">{esc(e["name"])}</a><small>{esc(e["country"])} · {esc(sector(e["sector"]))}</small></div></div>' for e in rel['similar'][:6])
    evidence=''
    for ev in risk['evidence']:
        evidence+=f'<tr><td><a href="{href(ev["url"])}" target="_blank" rel="noopener noreferrer">{esc(ev["title"])} →</a><div class="org-meta">{esc(ev["source"])} · {esc(ev.get("event_date",ev["date"])[:10])} · {ev.get("publications",1)} публикаций в группе</div></td><td class="score">+{ev["contribution"]:g}</td></tr>'
    related_evidence=''.join(f'<p style="font-size:12px"><a href="{org_url(e["org_id"])}">{esc(e["name"])}</a> · {esc(RELATIONS.get(e["relation_type"],e["relation_type"]))} · <a href="{href(e["evidence_url"])}">источник связи →</a></p>' for e in risk['relationships']['affected_peers'])
    sector_evidence=''.join(f'<a href="{org_url(e["org_id"])}">{esc(e["name"])}</a>' for e in risk['relationships'].get('sector_peers',[]))
    context_box=''
    if related_evidence or sector_evidence:
        context_box='<section class="card"><h2>Что повлияло косвенно</h2>'+related_evidence+(f'<p class="muted" style="font-size:12px">Наблюдаемые компании отрасли: {sector_evidence}</p>' if sector_evidence else '')+'<p class="panel-subtitle">Связь или одна отрасль не означают переход атаки.</p></section>'
    score_note='Свежих прямых сигналов нет. Индекс отражает только отраслевой или связанный контекст.' if risk['status']=='context_only' else 'Свежих прямых сигналов недостаточно для оценки.' if risk['score'] is None else 'Приоритет изучения сигналов за последние 30 дней.'
    return f'''<div class="breadcrumbs"><a href="/">Организации</a> / {esc(org['name'])}</div><div class="page-heading"><div class="profile-heading"><span class="org-avatar" aria-hidden="true">{initials(org['name'])}</span><div><p class="eyebrow">Карточка организации</p><h1>{esc(org['name'])}</h1><p class="lead">{esc(org['country'])} · {esc(sector(org['sector']))}</p></div></div><div class="button-row"><a class="button quiet" href="/organizations/edit/{quote(org_id,safe='')}">Редактировать</a><a class="button secondary" href="/graph?{esc(urlencode({'org_id':org_id}))}">Граф связей →</a></div></div>
    <div class="grid"><div><section class="card brief"><h2>Почему организация рассматривается в мониторинге</h2><p>{esc(brief['text'])}</p>{ai}</section><section class="card"><div class="section-head"><h2>Публикации и источники</h2><span class="tag info">{risk['counts']['events']} событий за 30 дней</span></div><p class="panel-subtitle">Каждая публикация сохраняет источник, дату и статус проверки.</p>{publications}</section><section class="card"><h2>Какие сигналы дали баллы</h2><p class="panel-subtitle">Повторы объединяются; вклад старых сигналов снижается.</p><div class="table-scroll"><table><thead><tr><th>Группа сообщений</th><th>Вклад</th></tr></thead><tbody>{evidence or '<tr><td colspan="2">Прямых сигналов для оценки нет</td></tr>'}</tbody></table></div></section>{context_box}</div><aside><section class="card"><h2>Приоритет мониторинга</h2><div class="risk-hero"><div class="risk-dial" style="--angle:{angle:g}deg;--dial-color:{color}"><div><strong>{value}</strong><small>из 100</small></div></div><div>{risk_badge(risk)}<p class="muted" style="font-size:11px;max-width:160px">{score_note}</p></div></div><div class="health-line">{CONFIDENCE[risk['confidence']['level']]}</div>{components}<p class="muted" style="font-size:10px;margin-top:20px">Источник данных: {risk['counts']['source_groups']} групп · {risk['counts']['reviewed_events']} проверенных событий. Количество источников не повышает балл.</p></section><section class="card"><h2>Документированные отношения</h2>{connections}<p style="margin-top:18px;font-size:12px"><a href="/graph?{esc(urlencode({'org_id':org_id}))}">Подробнее о связях →</a></p></section><section class="card"><h2>Состояние сбора</h2>{collection_status(risk['data_health'])}<p class="muted" style="font-size:11px;margin-top:12px">{risk['data_health']['sources_ok']} успешных источников · {risk['data_health']['sources_error']} ошибок за 24 часа</p><a href="/sources" style="font-size:11px">Открыть источники →</a></section></aside></div><div class="grid"><section class="card"><h2>Упомянуты вместе</h2><p class="panel-subtitle">Совместное упоминание требует проверки деловой связи.</p>{co or '<p class="empty-inline">Совместных упоминаний пока нет.</p>'}</section><section class="card"><h2>Похожие по стране или отрасли</h2><p class="panel-subtitle">Контекст для исследования; это не связи компаний.</p>{peers or '<p class="empty-inline">Совпадений пока нет.</p>'}</section></div><div class="note"><b>Что означает оценка.</b> {esc(risk['disclaimer'])} Проверка публикации не подтверждает успешную атаку. <a href="/method">Все правила расчёта →</a></div>'''
