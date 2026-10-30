"""Read-only web dashboard, bound to localhost by default; no frontend dependencies."""
from __future__ import annotations
import html
import json
import csv
import io
import secrets
import threading
import sqlite3
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit, urlencode
from .store import latest_scores, recent_items
from .scoring import compare_windows, MAX_SCORE, DIMENSION_LABELS
from .statistics import forecast_from_database
from .briefs import local_brief, brief_fingerprint

CSS = """
:root{color-scheme:dark;--bg:#09090d;--panel:rgba(22,20,29,.86);--panel2:#1e1b27;--line:#2a2731;--text:#f2f0f8;--muted:#aaa4b8;--accent:#a67cff;--amber:#dfba82;--green:#94c8ae}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{background:radial-gradient(ellipse at 100% 100%,#60319635 0,transparent 48%),radial-gradient(ellipse at 70% 35%,#39214c20 0,transparent 55%),var(--bg);background-attachment:fixed;color:var(--text);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Arial,sans-serif;margin:0}a{color:#c5a8ff;text-decoration:none}a:hover{color:#e4d7ff;text-decoration:underline}button,input,select,textarea{font:inherit}button,a,input,select,summary{ -webkit-tap-highlight-color:transparent}a:focus-visible,button:focus-visible,summary:focus-visible{outline:2px solid var(--accent);outline-offset:4px}
.sidebar{position:fixed;inset:0 auto 0 0;width:220px;background:rgba(13,12,18,.96);border-right:1px solid var(--line);padding:30px 18px;display:flex;flex-direction:column;z-index:10}.brand{display:flex;align-items:center;gap:10px;color:#f7f5fb;font-size:20px;letter-spacing:-.6px;font-weight:750}.brand:hover{text-decoration:none}.brandmark{display:grid;place-items:center;background:radial-gradient(circle at 30% 25%,#e0bbff,#a063e2 38%,#48216f 76%);border:1px solid #be8ef1;width:35px;height:35px;border-radius:50%;color:#fff4ff;box-shadow:0 0 25px #9649d94d,inset -5px -5px 12px #2b08477d}.brand-sub{font-size:10px;text-transform:uppercase;letter-spacing:2px;color:#797184;margin:8px 0 34px 44px}.nav-label{color:#746a83;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1.6px;padding:16px 12px 8px}.sidebar nav{display:flex;flex-direction:column;gap:5px}.sidebar nav a,.sidebar summary{color:#ada5b9;padding:10px 12px;display:block;border-radius:7px;cursor:pointer}.sidebar nav a:hover,.sidebar summary:hover{background:#1d1827;color:#f3eaff;text-decoration:none}.sidebar nav a.active{color:#decaff;background:#2d203e;border-left:2px solid #ab7aff;padding-left:10px}.nav-icon{display:inline-block;width:24px;color:#9c83bd}.sidebar details div a{font-size:12px;padding:6px 12px 6px 36px}.sidebar-foot{margin-top:auto;border-top:1px solid var(--line);padding:18px 9px 0;font-size:11px;color:var(--muted)}.live-dot{display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--green);margin-right:7px}.app-shell{margin-left:220px}.topbar{height:66px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;gap:16px;padding:0 36px;background:rgba(13,12,18,.84)}.topbar .breadcrumb{color:var(--muted);font-size:12px}.topbar .breadcrumb b{color:#dcd6e5;font-weight:500}.topbar .workspace-label{color:#92889f;font-size:11px;letter-spacing:.5px}.wrap{max-width:1540px;margin:0 auto;padding:28px 36px}.app-shell footer{padding-top:10px;padding-bottom:28px;color:#81778e;font-size:11px;max-width:1540px}.eyebrow{color:#b892ef;font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin:0 0 8px}.page-heading{display:flex;justify-content:space-between;align-items:center;gap:20px;margin-bottom:24px}h1{font-size:30px;letter-spacing:-.8px;line-height:1.2;margin:0 0 10px;font-weight:650}h2{font-size:16px;margin:0 0 15px;font-weight:650;letter-spacing:-.2px}h3{font-size:14px;margin:0 0 8px}.lead{color:var(--muted);max-width:820px;margin:0;font-size:13px}small,.muted{color:var(--muted)}.card{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:22px;margin:14px 0;box-shadow:0 8px 30px #00000016;backdrop-filter:blur(14px)}.metrics{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:16px;margin:24px 0}.metrics .card{margin:0}.metric-label{font-size:11px;color:#b1a7c0;display:flex;justify-content:space-between}.metric{font-size:33px;color:#faf8ff;font-weight:650;line-height:1.3;margin:8px 0;letter-spacing:-1px;font-variant-numeric:tabular-nums}.metric-caption{font-size:10px;color:#90859e}.metric-symbol{color:#a88acb}.accent-purple{color:#c7a1ff}.accent-amber{color:var(--amber)}.accent-rose{color:#e8a0b7}.section-head{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:16px}.section-head h2{margin:0}.count-label{color:#9a8eaa;font-weight:400;font-size:11px;margin-left:8px}.button,button{display:inline-flex;align-items:center;justify-content:center;gap:6px;background:linear-gradient(135deg,#a576eb,#8656cf);border:1px solid #ad84df;box-shadow:0 3px 18px #743fb329;color:#fff7ff;border-radius:6px;padding:9px 14px;font-weight:650;font-size:12px;cursor:pointer;text-decoration:none;white-space:nowrap}.button:hover,button:hover{background:#be95ff;color:#fff7ff;text-decoration:none}.button.secondary,button.secondary{background:#201a2b;border-color:#3b2f4c;color:#d1c3e5}.button.secondary:hover,button.secondary:hover{background:#332643;color:#fff}.button.quiet{background:transparent;border-color:var(--line);color:#c2b6d3}.button-row{display:flex;gap:9px;flex-wrap:wrap}.note{border:1px solid #393041;border-left:3px solid #a07ac6;padding:12px 16px;background:rgba(36,27,48,.7);color:#bab0c8;margin:18px 0;border-radius:6px;font-size:12px}.note b{color:#e9def5}.grid{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:20px}.grid>.card{min-width:0}.dashboard-grid{display:grid;align-items:start;grid-template-columns:minmax(0,2.2fr) minmax(270px,1fr);gap:20px}.dashboard-grid>.card{min-width:0;margin-top:0}.table-card{padding:0;overflow:hidden}.table-card .section-head{padding:20px 22px 0}.table-scroll{overflow-x:auto}table{width:100%;border-collapse:collapse;text-align:left}th{font-size:9px;text-transform:uppercase;letter-spacing:1px;color:#9a8eaa;padding:13px 15px;background:rgba(15,13,21,.7);font-weight:600;white-space:nowrap}td{border-top:1px solid #29242f;padding:15px;color:#c5bbd1;vertical-align:middle;font-size:12px}td strong{color:#efeaf6;font-weight:600}tr:hover td{background:rgba(55,38,75,.38)}.org-link{display:flex;align-items:center;gap:11px;min-width:170px}.org-avatar{display:grid;place-items:center;flex-shrink:0;width:32px;height:32px;background:#25202e;border:1px solid #403349;border-radius:8px;color:#cbb9df;font-size:11px;font-weight:700}.org-meta{font-size:10px;color:#9b8da8;margin-top:3px}.tag{display:inline-block;font-size:10px;padding:3px 8px;border:1px solid #42354c;border-radius:5px;color:#c4b4d4;white-space:nowrap}.tag.unknown{background:#231e2b;border-color:#3c3247;color:#ada0bc}.tag.low{background:#1c2c25;color:#a3cdb3;border-color:#354b3f}.tag.elevated{background:#30271d;color:#daba8d;border-color:#544432}.tag.high,.tag.critical{background:#35232e;color:#e5acbf;border-color:#5e3f50}.tag.info{background:#2a1f39;color:#c5a8ff;border-color:#4a355f}.score{font-weight:700;font-variant-numeric:tabular-nums;font-size:17px;color:#e8dbf5}.score small{font-size:10px;font-weight:400}.bar{display:inline-block;width:80px;max-width:100%;height:5px;vertical-align:middle;background:#30273a;border-radius:4px;overflow:hidden;margin-right:8px}.bar span{display:block;height:100%;background:#ad80e6}.score-track{width:64px;height:4px;background:#30273a;border-radius:4px;margin-top:6px}.score-track span{display:block;height:4px;background:#b48aef;border-radius:4px}.score-track.high span,.score-track.critical span{background:#d99bb5}.score-track.elevated span{background:#d4b17a}.score-track.low span{background:#ac82df}.filters{display:flex;gap:10px;align-items:center;flex-wrap:wrap;padding:15px 22px;border-bottom:1px solid var(--line);margin:0}.filters input[type=search]{flex:1;min-width:180px}.filters input,.filters select{font-size:11px;padding:8px 11px}.filter-label{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}form{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:16px 0}form.inline-form{display:inline-flex;margin:2px 6px 2px 0}select,input,textarea{background:#100d17;color:#eee6f8;padding:10px 12px;border:1px solid #39303f;border-radius:6px;max-width:100%}input:focus,select:focus,textarea:focus{outline:2px solid #a879e3;outline-offset:1px}label{font-size:12px;color:#b8abc6}.table-footer{display:flex;justify-content:space-between;gap:12px;padding:12px 22px;color:#96899f;font-size:10px;border-top:1px solid var(--line)}.signal-item{padding:15px 0;border-bottom:1px solid var(--line)}.signal-item:last-child{border-bottom:0;padding-bottom:0}.signal-item:first-of-type{padding-top:0}.signal-meta{display:flex;align-items:center;gap:8px;flex-wrap:wrap;font-size:10px;color:#9f8eae;margin-bottom:8px}.signal-item a.signal-title{font-size:12px;line-height:1.6;color:#e3daec;display:block}.signal-source{font-size:10px;color:#9a88aa;margin-top:7px}.empty-state{text-align:center;padding:34px 20px}.empty-icon{font-size:28px;color:#826793;margin-bottom:12px}.empty-state h3{color:#d8c8e8;margin-bottom:7px}.empty-state p{color:#a697b3;font-size:12px;max-width:420px;margin:0 auto 18px}.empty-inline{padding:20px 0;color:#aa99b8;font-size:12px}.health-line{display:flex;gap:9px;align-items:center;font-size:11px;color:#bba8cb}.health-dot{width:6px;height:6px;border-radius:50%;background:#98bfa7;flex-shrink:0}.health-dot.warning{background:#d1b387}.health-dot.unknown{background:#8d7b9f}.monitor-note{display:flex;justify-content:space-between;align-items:center;gap:18px;border:1px solid var(--line);border-radius:8px;background:rgba(23,18,30,.84);padding:13px 18px;margin-top:18px}.monitor-note p{color:#aa98ba;font-size:11px;margin:0}.tabs{display:flex;gap:20px;padding:0 22px;border-bottom:1px solid var(--line);overflow:auto}.tabs a{padding:12px 0;color:#a08cb3;font-size:11px;white-space:nowrap}.tabs a.current{color:#e4cdff;border-bottom:2px solid #ae7bf2;background:linear-gradient(0deg,#9d64e515,transparent)}.profile-heading{display:flex;align-items:center;gap:16px}.profile-heading .org-avatar{width:48px;height:48px;font-size:17px;border-radius:12px}.breadcrumbs{font-size:11px;color:#9b85b0;margin-bottom:22px}.risk-hero{display:flex;align-items:center;gap:25px;padding:5px 0 19px}.risk-dial{width:118px;height:118px;flex-shrink:0;border-radius:50%;background:conic-gradient(var(--dial-color,#b68aef) var(--angle,0deg),#30263d 0deg);padding:7px;display:grid;place-items:center}.risk-dial>div{border-radius:50%;width:104px;height:104px;background:var(--panel);display:grid;place-content:center;text-align:center}.risk-dial strong{font-size:36px;letter-spacing:-1px;line-height:1.1}.risk-dial small{font-size:10px;margin-top:4px}.component{margin-top:19px}.component-title{display:flex;justify-content:space-between;font-size:12px;margin-bottom:7px;color:#dacbe8}.component .bar{width:100%;height:5px}.component p{color:#b09cc0;font-size:11px;margin:7px 0 0}.evidence{padding:14px 0;border-bottom:1px solid var(--line)}.evidence:last-child{border:0}.brief{border-top:2px solid #8a59c2}.brief p{font-size:12px;color:#c0acd1}.references{font-size:12px;padding-left:19px}.references li{margin:8px 0}.connection-item{display:flex;align-items:center;gap:10px;padding:13px 0;border-bottom:1px solid var(--line)}.connection-item:last-child{border:0}.connection-item .connection-info{flex:1;min-width:0}.connection-item a{color:#e1ccef;font-size:12px}.connection-item small{display:block;font-size:10px;margin-top:3px}.good{color:#a9cab4}.warning{color:var(--amber)}code{padding:2px 5px;background:#2a2035;border-radius:4px;font-size:12px}svg{max-width:100%;height:auto}.panel-subtitle{font-size:11px;color:#a08fb1;margin:-7px 0 15px}
@media(min-width:1600px){.wrap{padding-left:45px;padding-right:45px}}
@media(max-width:1120px){.sidebar{width:190px;padding-left:12px;padding-right:12px}.app-shell{margin-left:190px}.wrap{padding:24px}.topbar{padding:0 24px}.dashboard-grid{grid-template-columns:1fr}.metrics{gap:10px}.metrics .card{padding:17px}}
@media(max-width:760px){.sidebar{position:static;width:auto;padding:16px;border-right:0;border-bottom:1px solid var(--line);display:block}.brand-sub,.nav-label,.sidebar-foot{display:none}.sidebar .brand{margin-bottom:14px}.sidebar nav{flex-direction:row;flex-wrap:wrap;gap:2px}.sidebar nav a,.sidebar summary{font-size:11px;padding:6px 9px}.nav-icon{width:16px}.sidebar details{position:relative}.sidebar details>div{position:absolute;right:0;top:34px;min-width:220px;background:#1d1627;border:1px solid #44344f;padding:12px;z-index:20;border-radius:8px}.sidebar details div a{padding:8px 12px}.app-shell{margin-left:0}.topbar{height:47px;padding:0 18px}.workspace-label{display:none}.wrap{padding:22px 16px}.page-heading{align-items:flex-start;flex-direction:column;gap:15px}h1{font-size:25px}.metrics{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.metric{font-size:28px}.grid{grid-template-columns:1fr;gap:0}.card{padding:18px}.table-card{padding:0}.table-card .section-head{padding:18px 15px 0}.filters{padding:12px 15px}.filters select{flex:1;min-width:100px}.monitor-note{align-items:flex-start;flex-direction:column}.dashboard-grid{gap:0}.risk-hero{gap:20px}.table-footer{padding:12px 15px}.topbar .breadcrumb{font-size:11px}td{padding:12px;font-size:11px}.app-shell footer{font-size:10px}.tabs{padding:0 15px}.profile-heading{align-items:flex-start}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}

.overview-heading{padding:12px 0 8px;align-items:flex-end}.overview-heading h1{font-size:42px;line-height:1.12;letter-spacing:-1.7px;font-weight:550;margin:12px 0 16px}.hero-accent{background:linear-gradient(100deg,#f3eaff,#bb8de9 80%);background-clip:text;-webkit-background-clip:text;color:transparent}.overview-heading .lead{max-width:650px;font-size:13px}.eyebrow-pill{display:inline-flex;align-items:center;gap:7px;border:1px solid #44314f;background:#25182e80;border-radius:30px;padding:5px 10px;letter-spacing:.7px;color:#c4a4dd}.eyebrow-pill::before{content:"";width:5px;height:5px;border-radius:50%;background:#c08aef;box-shadow:0 0 8px #bc82f1}.intro-panel{background:linear-gradient(115deg,#23172c99,#141019b3);border-color:#45324f}.intro-panel .section-head{margin-bottom:10px}.intro-panel h2{color:#ece0fa}
@media(max-width:760px){.overview-heading{padding-top:3px;gap:20px}.overview-heading h1{font-size:32px;letter-spacing:-1.1px}.overview-heading .button-row{width:100%}.overview-heading .button-row .button{flex:1}.topbar{gap:10px}.topbar .breadcrumb{min-width:0}.topbar .tag{font-size:9px;padding:3px 6px}.intro-panel .section-head{align-items:flex-start}.intro-panel .lead{font-size:12px}}
"""


def csv_safe(value):
    """Prevent source-supplied titles from executing spreadsheet formulas in CSV exports."""
    text='' if value is None else str(value)
    return "'"+text if text.lstrip().startswith(('=', '+', '-', '@')) else text


def esc(v) -> str:
    return html.escape(str(v if v is not None else ""),quote=True)


def page(title: str, body: str) -> bytes:
    from .workspace_ui import shell
    return shell(title, body, CSS)


def badge(status: str) -> str:
    if status == "insufficient_evidence":
        return '<span class="tag unknown">Недостаточно данных</span>'
    if status == "limited_evidence":
        return '<span class="tag unknown">Низкое покрытие источников</span>'
    return '<span class="tag">Мониторинг</span>'


def _select_options(values, selected, label):
    options=f'<option value="">{esc(label)}</option>'
    for value in values:
        options+=f'<option value="{esc(value)}"'+(' selected' if value==selected else '')+f'>{esc(value)}</option>'
    return options


def home(con: sqlite3.Connection, query: dict | None = None, *, collecting=False) -> bytes:
    from .workspace_ui import overview
    progress=('<div class="note" role="status">Идёт сбор новостей. Обзор обновится автоматически, когда появятся результаты.</div>' if collecting else '')
    return page('Обзор',progress+overview(con, query or {}))


def safe_href(url: str) -> str:
    return esc(url) if urlsplit(url).scheme in ("http","https") else "#"


def org_page(con: sqlite3.Connection, org_id: str) -> bytes | None:
    from .workspace_ui import organization_detail
    body = organization_detail(con, org_id)
    if body is None:
        return None
    org = con.execute('SELECT name FROM organizations WHERE id=?', (org_id,)).fetchone()
    return page(org['name'], body)


def candidates_page(con: sqlite3.Connection, query: dict) -> bytes:
    from .entity_graph import list_candidates
    country=(query.get('country') or [''])[0][:70]
    sector=(query.get('sector') or [''])[0][:110]
    status=(query.get('status') or ['pending'])[0][:20]
    if status not in ('pending','approved','rejected',''):
        status='pending'
    all_rows=list_candidates(con,status='',limit=1000)
    country_options=_select_options(sorted({r['country'] for r in all_rows if r['country']}),country,'Все страны')
    sector_options=_select_options(sorted({r['sector'] for r in all_rows if r['sector']}),sector,'Все отрасли')
    status_options=_select_options(['pending','approved','rejected'],status,'Любой статус')
    filtered=list_candidates(con,country=country,sector=sector,status=status,limit=500)
    trs=''
    for r in filtered:
        approved=(f'<a href="/org/{esc(r["reviewed_org_id"])}">В мониторинге</a>' if r['reviewed_org_id'] else '')
        trs+=f'<tr><td><a href="/candidate/{r["id"]}"><b>{esc(r["name"])}</b></a></td><td>{esc(r["country"] or "неизвестна")}</td><td>{esc(r["sector"] or "неизвестна")}</td><td>{r["publications"]}</td><td>{r["source_groups"]}</td><td>{esc(r["status"])} {approved}</td></tr>'
    return page('Кандидаты из инцидентов',f'''<h1>Организации, обнаруженные по публикациям</h1>
      <p class="lead">Программа извлекает предположительные названия из публичных сообщений. Никто автоматически не проверяет их достоверность: открой карточку и первоисточник, затем нажми «Добавить в мониторинг» либо «Отклонить». Это НЕ подтверждённые жертвы.</p>
      <form method="get" action="/candidates"><label>Страна <select name="country">{country_options}</select></label><label>Отрасль <select name="sector">{sector_options}</select></label><label>Состояние <select name="status">{status_options}</select></label><button>Применить</button></form>
      <div class="note">Если страна или отрасль не указаны в исходном сообщении, программа оставляет поле пустым. Она не угадывает страну по домену СМИ.</div>
      <div class="card" style="overflow-x:auto"><table><tr><th>Организация</th><th>Страна</th><th>Отрасль</th><th>Публикации</th><th>Группы источников</th><th>Статус</th></tr>{trs or '<tr><td colspan="6">Пока нет кандидатов</td></tr>'}</table></div>
      <p><small>Открой название кандидата → изучи первоисточник → укажи страну и отрасль → выбери решение. Пустые поля означают неизвестные данные; не угадывай их.</small></p>''')


def candidate_page(con: sqlite3.Connection, id: int, csrf: str = "") -> bytes | None:
    from .entity_graph import candidate_evidence
    row=con.execute('SELECT * FROM entity_candidates WHERE id=?',(id,)).fetchone()
    if not row:return None
    evidence=candidate_evidence(con,id)
    li=''.join(f'<li>{esc((e["published_at"] or "")[:10])} · <a href="{safe_href(e["url"])}" target="_blank" rel="noopener noreferrer">{esc(e["source_name"])}</a> · {esc(e["kind"])}</li>' for e in evidence)
    from .web_controls import candidate_review_actions
    actions=candidate_review_actions(con,row,csrf)
    return page(row['name'],f'''<p><a href="/candidates">← Кандидаты</a></p><h1>{esc(row["name"])}</h1>
        <p>Страна: {esc(row["country"] or "не установлена")}; отрасль: {esc(row["sector"] or "не установлена")}; статус: {esc(row["status"])}</p><p><strong>Это предложение автоматического извлечения, а не результат проверки.</strong> Решение принимаешь ты; при добавлении начнётся мониторинг, но не будет считаться доказанным взломом.</p>
        <div class="note">Название взято из публичного сообщения. Это может быть ошибка агрегатора или заявление злоумышленников. Никакой прогноз взлома из одного упоминания не следует.</div>
        <div class="card"><h2>Первичные публикации</h2><ul>{li}</ul></div>{actions}''')

def analytics_page(con: sqlite3.Connection) -> bytes:
    from .analytics import aggregate
    data=aggregate(con)
    def bars(rows,filterkey):
        if not rows:return '<p class="muted">Данных пока нет</p>'
        top=max(1,rows[0]['publications'])
        return ''.join(f'<div class="evidence"><a href="/candidates?{urlencode({filterkey:r["label"]})}">{esc(r["label"])}</a><span style="float:right">{r["publications"]}</span>'
               f'<div class="bar" style="width:75%;height:9px"><span style="width:{max(1,round(100*r["publications"]/top))}%"></span></div></div>' for r in rows)
    cb=bars(data['countries'],'country')
    sb=bars(data['sectors'],'sector')
    daily=''.join(f'<tr><td>{esc(r["day"])}</td><td>{r["publications"]}</td></tr>' for r in data['daily'])
    return page('Сводная статистика',f'''<h1>Статистика опубликованных сигналов</h1>
      <p class="lead">Видно, где и в каких отраслях упоминались организации в публичных сообщениях. Данные зависят от охвата источников и не измеряют частоту реальных атак.</p>
      <div class="grid"><div class="card"><h2>По странам организаций</h2>{cb}</div><div class="card"><h2>По отраслям</h2>{sb}</div></div>
      <div class="card"><h2>Публикации по дням (последние 30 дат в базе)</h2><table><thead><tr><th>Дата</th><th>Уникальных URL</th></tr></thead>{daily}</table></div>
      <p class="muted">Страна издателя, язык статьи и страна пострадавшей организации — разные признаки. Неизвестные значения остаются неизвестными.</p>''')


def incidents_page(con: sqlite3.Connection, query: dict) -> bytes:
    kind=(query.get('kind') or ['all'])[0]
    allowed={'all','claim','incident_report','threat_statement','advisory','context'}
    if kind not in allowed:kind='all'
    country=(query.get('country') or [''])[0][:70]
    sector=(query.get('sector') or [''])[0][:110]
    sql='''WITH docs AS (
       SELECT d.url_key,d.url,d.title,d.source_name,d.published_at,d.kind FROM discovery d
       UNION ALL SELECT i.url_key,i.url,i.title,i.source_name,i.published_at,i.kind FROM items i)
       SELECT * FROM docs WHERE 1=1'''
    params=[]
    if kind!='all':sql+=' AND kind=?';params.append(kind)
    if country or sector:
        parts=[];args=[]
        if country:parts.append('c.country=?');args.append(country)
        if sector:parts.append('c.sector=?');args.append(sector)
        match=' AND '.join(parts)
        parts2=[];args2=[]
        if country:parts2.append('o.country=?');args2.append(country)
        if sector:parts2.append('o.sector=?');args2.append(sector)
        sql+=f''' AND (EXISTS (SELECT 1 FROM candidate_evidence e JOIN entity_candidates c
              ON e.candidate_id=c.id WHERE e.url_key=docs.url_key AND {match})
           OR EXISTS (SELECT 1 FROM items i JOIN mentions m ON m.item_id=i.id
              JOIN organizations o ON o.id=m.org_id WHERE i.url_key=docs.url_key AND {' AND '.join(parts2)}))'''
        params.extend(args+args2)
    sql+=' GROUP BY url_key ORDER BY published_at DESC LIMIT 250'
    rows=con.execute(sql,params).fetchall()
    countries=[r['country'] for r in con.execute('''SELECT DISTINCT country FROM (
         SELECT country FROM organizations UNION SELECT country FROM entity_candidates) WHERE country!='' ORDER BY country''')]
    sectors=[r['sector'] for r in con.execute('''SELECT DISTINCT sector FROM (
         SELECT sector FROM organizations UNION SELECT sector FROM entity_candidates) WHERE sector!='' ORDER BY sector''')]
    koptions=_select_options(sorted(allowed-{'all'}),kind,'Все типы')
    trs=''.join(f'<tr><td>{esc((r["published_at"] or "")[:10])}</td><td><a href="{safe_href(r["url"])}" rel="noopener noreferrer" target="_blank">{esc(r["title"])}</a></td><td>{esc(r["source_name"])}</td><td>{esc(r["kind"])}</td></tr>' for r in rows)
    return page('Инциденты и заявления',f'''<h1>Лента публичных сообщений</h1>
       <p class="lead">Включает сообщения как про отслеживаемые, так и про ещё не разобранные организации. Дата может быть временем публикации или индексирования, а не временем атаки.</p>
       <form method="get" action="/incidents"><label>Страна <select name="country">{_select_options(countries,country,'Любая')}</select></label>
       <label>Отрасль <select name="sector">{_select_options(sectors,sector,'Любая')}</select></label>
       <label>Тип <select name="kind">{koptions}</select></label><button>Применить</button><a href="/incidents">Сброс</a></form>
       <div class="card"><table><thead><tr><th>Дата</th><th>Публикация</th><th>Источник</th><th>Статус текста</th></tr></thead>{trs or '<tr><td colspan="4">Нет подходящих материалов</td></tr>'}</table></div>
       <p class="muted">Это не реестр подтверждённых успешных взломов. Проверка первоисточника обязательна.</p>''')


def events_page(con: sqlite3.Connection, query: dict) -> bytes:
    kinds = ("all","claim","incident_report","threat_statement","advisory","context")
    selected = query.get("kind",["all"])[0]
    if selected not in kinds:
        selected = "all"
    sql = "SELECT i.*,GROUP_CONCAT(o.name, ', ') AS org_names FROM items i LEFT JOIN mentions m ON m.item_id=i.id LEFT JOIN organizations o ON o.id=m.org_id"
    args = []
    if selected != "all":
        sql += " WHERE kind=?"
        args.append(selected)
    sql += " GROUP BY i.id ORDER BY COALESCE(i.published_at,i.collected_at) DESC LIMIT 300"
    rows = con.execute(sql,args).fetchall()
    options = "".join(f'<option value="{esc(k)}" {"selected" if selected==k else ""}>{esc(k)}</option>' for k in kinds)
    trs = "".join(f'<tr><td>{esc((r["published_at"] or "")[:10])}</td><td><a href="{safe_href(r["url"])}" target="_blank" rel="noopener noreferrer">{esc(r["title"])}</a><br><small>{esc(r["source_name"])}</small></td><td>{esc(r["org_names"])}</td><td>{esc(r["kind"])}</td><td>{esc(r["review_status"])}</td></tr>' for r in rows)
    body = f'<h1>Журнал источников</h1><p class="lead">Одна строка = одна публикация. Повторы между издателями могут относиться к одному событию.</p><form><label>Фильтр: <select name="kind">{options}</select></label><button>Применить</button></form><div class="card" style="overflow-x:auto"><table><tr><th>Дата</th><th>Публикация</th><th>Организации</th><th>Категория</th><th>Ручная проверка</th></tr>{trs}</table></div>'
    return page("Публикации",body)


def discovery_page(con: sqlite3.Connection) -> bytes:
    rows=con.execute("""SELECT d.*,s.organization_names_json,s.suggested_kind,s.rationale
       FROM discovery d LEFT JOIN discovery_suggestions s ON s.url_key=d.url_key
       ORDER BY d.published_at DESC LIMIT 250""").fetchall()
    total=con.execute("SELECT count(*) FROM discovery").fetchone()[0]
    analysed=con.execute("SELECT count(*) FROM discovery_suggestions").fetchone()[0]
    candidates=con.execute("SELECT candidate_name,count(*) AS n FROM discovery WHERE candidate_name<>'' GROUP BY candidate_name ORDER BY n DESC LIMIT 20").fetchall()
    links=' '.join(f'<span class="tag">{esc(r["candidate_name"])} · {r["n"]}</span>' for r in candidates)
    trs=''
    for r in rows:
        names=[]
        if r['organization_names_json']:
            try:names=json.loads(r['organization_names_json'])
            except ValueError:names=[]
        suggested=', '.join(str(n) for n in names[:5]) if isinstance(names,list) else ''
        hint = (f'<span class="tag unknown">ИИ: предложение к проверке</span><br><small>{esc(suggested or "без названия")}'
                f' · {esc(r["suggested_kind"])} · {esc(r["rationale"][:150])}</small>' if r['organization_names_json'] else '—')
        trs += f'<tr><td>{esc(r["published_at"][:10])}</td><td><a href="{safe_href(r["url"])}" target="_blank" rel="noopener noreferrer">{esc(r["title"])}</a><br><small>{esc(r["source_name"])}</small></td><td>{esc(r["candidate_name"]) or "—"}</td><td>{hint}</td><td>{esc(r["kind"])}</td></tr>'
    return page('Неотнесённые публикации',f'''<h1>Каталог публикаций вне списка наблюдения</h1>
<p class="lead">Ранее эти сообщения отбрасывались. Сейчас они сохраняются для проверки. Необязательная локальная ИИ-модель может предложить названия организаций, но не добавляет их автоматически и не изменяет индекс.</p>
<div class="card"><div class="metric">{total}</div><small>Сохранённых уникальных сообщений</small><p>{links}</p><p class="muted">{analysed} сообщений предварительно обработаны локальной моделью. Все предложения требуют ручной проверки.</p></div>
<div class="card" style="overflow-x:auto"><table><tr><th>Дата</th><th>Публикация</th><th>Из названия источника</th><th>Локальный ИИ</th><th>Тип</th></tr>{trs}</table></div>''')


def sources_page(con: sqlite3.Connection, csrf: str = '', notice: str = '') -> bytes:
    from .admin_web import sources_settings_page
    return sources_settings_page(con,csrf,notice)


def research_page(con: sqlite3.Connection) -> bytes:
    from .history import readiness
    state=readiness(con)
    done=state['fully_eligible_weekly_snapshots']
    first=state['first_success'] or 'нет'
    last=state['last_success'] or 'нет'
    return page('Историческая модель',f"""<h1>Историческая выборка и валидация</h1>
    <div class="metrics"><div class="card"><small>Начало сбора</small><div class="metric" style="font-size:17px">{esc(first)}</div></div>
    <div class="card"><small>Последний успешный день</small><div class="metric" style="font-size:17px">{esc(last)}</div></div>
    <div class="card"><small>Дней успешного сбора</small><div class="metric">{state['successful_collection_days']}</div></div>
    <div class="card"><small>Готовых дат для исторических срезов</small><div class="metric">{done}</div></div></div>
    <div class="card"><h2>Подготовка выборки</h2><p>Нужно минимум 28 дней наблюдений до даты оценки и 14 дней после неё для проверки исхода. При сборе задним числом нельзя учитывать публикации, фактически полученные позже даты оценки.</p>
    <p><code>python -m threatwatch history-status</code></p>
    <p><code>python -m threatwatch prepare-history exports/history_candidates.csv</code></p>
    <p><code>python -m threatwatch validate-model exports/verified_history.csv</code></p>
    <p><strong>Новая проверка графа v5:</strong></p>
    <p><code>python -m threatwatch prepare-graph-history exports/graph_unlabelled.csv</code></p>
    <p><code>python -m threatwatch validate-graph exports/graph_verified.csv</code></p>
    <p>Сравниваются прямые и графовые признаки на ОДНОЙ хронологической выборке; графовый контекст не повышает автоматически индекс и не передаёт статус жертвы соседним компаниям.</p>
    <p><strong>ВАЖНО:</strong> модель не обучается на неподписанных примерах; нулевой исход требует независимого подтверждения, а не отсутствия статей. Н/Д не равен нулю. Порог в 80 размеченных наблюдений — технический минимум, не гарантия достоверности вероятностей.</p></div>""")


def cybermap_page(con: sqlite3.Connection) -> bytes:
    from .cybermap import recent_observations, MAP_URL, STAT_URL, DATA_URL, NEWS_URL, WIDGET_URL
    rows=recent_observations(con,limit=120)
    table=''.join(
        f'<tr><td>{esc(r["observed_date"])}</td><td>{esc(r["country"])}</td>'
        f'<td>{esc(r["category"])}</td><td>{esc(r["measurement"])}</td>'
        f'<td>{esc(r["value"])} {esc(r["unit"])}</td>'
        f'<td><a href="{safe_href(r["source_url"])}" rel="noopener noreferrer" target="_blank">Источник</a></td></tr>'
        for r in rows)
    kaspersky_news=con.execute("""SELECT published_at,title,url,source_name
      FROM items WHERE source_name LIKE '%Kaspersky%' OR source_name LIKE '%Securelist%'
      UNION ALL SELECT published_at,title,url,source_name FROM discovery
      WHERE source_name LIKE '%Kaspersky%' OR source_name LIKE '%Securelist%'
      ORDER BY published_at DESC LIMIT 15""").fetchall()
    news=''.join(f'<li>{esc((r["published_at"] or "")[:10])} · '
        f'<a href="{safe_href(r["url"])}" target="_blank" rel="noopener noreferrer">{esc(r["title"])}</a>'
        f' <small>{esc(r["source_name"])}</small></li>' for r in kaspersky_news)
    content = f"""<h1>Киберкарта Kaspersky</h1>
<p class="lead">Официальный виджет Kaspersky Cybermap: визуальная справка о детектированиях средствами защиты, НЕ список взломанных организаций. Счётчики карты нельзя использовать как вероятность взлома компании.</p>
<div class="card"><h2>Интерактивная карта — официальный виджет</h2>
<iframe title="Kaspersky Cybermap — официальный виджет" loading="lazy" src="{safe_href(WIDGET_URL)}"
  referrerpolicy="no-referrer" style="width:100%;height:460px;border:0;border-radius:8px;background:#111" allowfullscreen></iframe>
<p><small>Визуализация предоставляется Kaspersky. Если браузер блокирует iframe, открой официальный сайт.</small></p>
<p><a href="{safe_href(MAP_URL)}" target="_blank" rel="noopener noreferrer">Карта</a> ·
<a href="{safe_href(STAT_URL)}" target="_blank" rel="noopener noreferrer">Статистика</a> ·
<a href="{safe_href(DATA_URL)}" target="_blank" rel="noopener noreferrer">Источники / OAS–RMW</a> ·
<a href="{safe_href(NEWS_URL)}" target="_blank" rel="noopener noreferrer">Новости</a></p></div>
<div class="card"><h2>Источники детектирований</h2><p class="muted">OAS — проверка файлов при доступе; ODS — ручная проверка; MAV — почтовый антивирус; WAV — веб-антивирус; IDS — сетевые детектирования; VUL — уязвимости; KAS — спам; RMW — программы-вымогатели. Метрики относятся к событиям продуктов Kaspersky, а не к компрометации отдельных компаний.</p></div>
<div class="card"><h2>Исследования и новости Kaspersky в нашей базе</h2><p class="muted">Публикации Securelist из стандартного RSS; не являются телеметрией Cybermap.</p><ul>{news or '<li>Сначала запустите сбор RSS — либо откройте оригинальную страницу новостей по ссылке выше</li>'}</ul></div>
<div class="card"><h2>Наблюдения, вручную внесённые со страницы статистики</h2>
<p class="muted">Импорт через <code>python -m threatwatch import-cybermap file.csv</code>. Эти агрегаты не изменяют индекс организаций, не считаются атаками и не загружаются со скрытых API.</p>
<table><thead><tr><th>Дата</th><th>Страна</th><th>Тип</th><th>Показатель</th><th>Значение</th><th>Ссылка</th></tr></thead><tbody>{table or '<tr><td colspan="6">Пока нет ручных наблюдений</td></tr>'}</tbody></table></div>"""
    return page('Kaspersky Cybermap',content)


def quality_page(con: sqlite3.Connection) -> bytes:
    articles=con.execute("""SELECT COUNT(*) FROM (
          SELECT url_key FROM discovery UNION SELECT url_key FROM items)""").fetchone()[0]
    candidates=con.execute('SELECT COUNT(*) FROM entity_candidates').fetchone()[0]
    evidence=con.execute('SELECT COUNT(*) FROM candidate_evidence').fetchone()[0]
    body=f'''<h1>Качество извлечения организаций</h1>
    <p class="lead">Этот раздел помогает проверить, насколько хорошо система распознаёт компании и учреждения в статьях. Точность без независимой ручной разметки измерить невозможно.</p>
    <div class="metrics"><div class="card"><small>Статей</small><div class="metric">{articles}</div></div><div class="card"><small>Кандидатов</small><div class="metric">{candidates}</div></div><div class="card"><small>Связей кандидат — статья</small><div class="metric">{evidence}</div></div></div>
    <div class="card"><h2>Проверка качества</h2>
      <p><code>python -m threatwatch export-entity-audit exports/entity_review.csv --size 100</code></p>
      <p>Открой CSV и заполни <code>reviewed=yes</code> и <code>expected_organizations</code> для каждой проверенной статьи. Укажи все действительно упомянутые организации через символ | либо NONE, если их нет.</p>
      <p><code>python -m threatwatch evaluate-entity-audit exports/entity_review.csv</code></p>
      <p>Получишь precision, recall, F1 и примеры пропусков. Это качество извлечения названий, а не точность прогнозирования взломов.</p></div>'''
    return page('Качество данных',body)


def graph_page(con: sqlite3.Connection, query: dict, csrf: str = "") -> bytes:
    from .graph_temporal import graph_context_at
    from .entity_graph import organization_connections
    import datetime as dt
    names=con.execute('''SELECT o.id,o.name,o.country,o.sector FROM organizations o LEFT JOIN organization_preferences p ON p.org_id=o.id WHERE COALESCE(p.active,1)=1 ORDER BY o.name''').fetchall()
    country=(query.get('country') or [''])[0][:6]
    sector=(query.get('sector') or [''])[0][:120]
    selected=(query.get('org_id') or [''])[0][:150]
    date_text=(query.get('as_of') or [''])[0][:10]
    try: day=dt.date.fromisoformat(date_text) if date_text else dt.datetime.now(dt.timezone.utc).date()
    except ValueError: day=dt.datetime.now(dt.timezone.utc).date()
    countries=sorted({x['country'] for x in names if x['country']})
    sectors=sorted({x['sector'] for x in names if x['sector']})
    filtered=[r for r in names if (not country or r['country']==country) and (not sector or r['sector']==sector)]
    if not selected and filtered:
        eligible={r['id'] for r in filtered}
        connected=con.execute('''SELECT org_id,COUNT(*) AS ties FROM (
            SELECT source_org_id AS org_id FROM organization_relations WHERE recorded_at<=?
            UNION ALL SELECT target_org_id FROM organization_relations WHERE recorded_at<=?)
            GROUP BY org_id ORDER BY ties DESC,org_id''',(day.isoformat()+'T23:59:59+00:00',day.isoformat()+'T23:59:59+00:00')).fetchall()
        selected=next((r['org_id'] for r in connected if r['org_id'] in eligible),'')
        if not selected:
            co=con.execute('''SELECT a.org_id,COUNT(DISTINCT a.item_id) AS articles
                FROM mentions a JOIN mentions b ON a.item_id=b.item_id AND a.org_id!=b.org_id
                JOIN items i ON i.id=a.item_id WHERE i.review_status!='rejected' AND i.published_at<=?
                GROUP BY a.org_id ORDER BY articles DESC,a.org_id''',(day.isoformat()+'T23:59:59+00:00',)).fetchall()
            selected=next((r['org_id'] for r in co if r['org_id'] in eligible),'')
    opts=''.join(f'<option value="{esc(r["id"])}"'+(' selected' if selected==r['id'] else '')+f'>{esc(r["name"])}</option>' for r in filtered)
    form=f'''<form method="get" action="/graph">
      <label>Страна <select name="country">{_select_options(countries,country,'Любая')}</select></label>
      <label>Отрасль <select name="sector">{_select_options(sectors,sector,'Любая')}</select></label>
      <label>Организация <select name="org_id"><option value="">Выбери</option>{opts}</select></label>
      <label>На дату <input name="as_of" type="date" value="{esc(day.isoformat())}"></label>
      <button>Показать</button></form>'''
    body='<h1>Связи между организациями</h1><p class="lead">Выбери организацию: фиолетовые сплошные линии — подтверждённые отношения, жёлтые — предложения, пунктир — совместные упоминания. Первоначально граф пуст, потому что автоматическое совпадение названий не доказывает отношений.</p>'+form
    if selected and any(r['id']==selected for r in filtered):
        ctx=graph_context_at(con,selected,day)
        rel=organization_connections(con,selected,limit=30)
        rel['documented']=[r for r in rel['documented'] if r['recorded_at'][:10]<=day.isoformat() and (r['review_status']!='verified' or (r['verified_at'] and r['verified_at'][:10]<=day.isoformat()))]
        def _relation_row(r):
            action=''
            excerpt=f'<div class="org-meta">{esc(r.get("evidence_excerpt", ""))}</div>' if r.get('evidence_excerpt') else ''
            if csrf and r['review_status']!='verified':
                action=(f'<form class="inline-form" method="post" action="/relations/verify/{int(r["id"])}">'
                        f'<input type="hidden" name="csrf" value="{esc(csrf)}">'
                        f'<button class="secondary" title="Только после проверки первоисточника">Подтвердить</button></form>')
            return (f'<tr><td><a href="/org/{esc(r["other_id"])}">{esc(r["other_name"])}</a></td>'
                    f'<td>{esc(r["relation_type"])}{excerpt}</td><td>{esc(r["review_status"])}</td>'
                    f'<td><a href="{safe_href(r["evidence_url"])}" target="_blank" rel="noopener noreferrer">Источник</a> {action}</td></tr>')
        entries=''.join(_relation_row(r) for r in rel['documented'])
        pending_relations=[r for r in rel.get('pending',[]) if r['recorded_at'][:10]<=day.isoformat()]
        if pending_relations:
            pending_rows=''.join(f'<tr><td><a href="/candidate/{int(r["target_candidate_id"])}">{esc(r["other_name"])}</a></td><td>{esc(r["relation_type"])}</td><td><a href="{safe_href(r["evidence_url"])}" target="_blank" rel="noopener noreferrer">Источник</a></td><td><span class="tag unknown">Организация требует проверки</span></td></tr>' for r in pending_relations)
            body+='<div class="card"><h2>Предложения связанных организаций</h2><p class="panel-subtitle">Эти организации ещё не добавлены в мониторинг. Откройте карточку кандидата и проверьте источник; принятие организации не подтверждает отношение.</p><div class="table-scroll"><table><thead><tr><th>Организация</th><th>Предполагаемый тип</th><th>Источник</th><th>Статус</th></tr></thead><tbody>'+pending_rows+'</tbody></table></div></div>'

        stats=ctx['raw_counts']
        from .graph_render import relation_svg
        focal=next(r for r in filtered if r['id']==selected)
        svg=relation_svg(selected,focal['name'],rel['documented'], co_mentions=rel['co_mentioned'])
        body+=svg
        from .admin_web import relation_editor
        body+=relation_editor(con,selected,csrf) if csrf else ''
        body+=f'''<div class="metrics"><div class="card"><small>Проверенных связей на дату</small><div class="metric">{stats['documented_neighbors']}</div></div><div class="card"><small>Публикаций о связанных</small><div class="metric">{stats['neighbor_publication_groups']}</div></div><div class="card"><small>Публикаций по отрасли</small><div class="metric">{stats['sector_publication_groups']}</div></div><div class="card"><small>Публикаций по стране</small><div class="metric">{stats['country_publication_groups']}</div></div></div>
        <div class="card"><h2>Отношения и ссылки</h2><table><tr><th>Организация</th><th>Тип</th><th>Проверка</th><th>Источник</th></tr>{entries or '<tr><td colspan="4">Нет внесённых отношений</td></tr>'}</table></div>'''
        co_rows=''.join(f'<li><a href="/org/{esc(r["id"])}">{esc(r["name"])}</a> — {r["articles"]} общих публикаций; <a href="{safe_href(r["example_url"])}">пример</a></li>' for r in rel['co_mentioned'])
        peer_rows=''.join(f'<li><a href="/org/{esc(r["id"])}">{esc(r["name"])}</a> — {esc(r["country"])} / {esc(r["sector"])}</li>' for r in rel['similar'])
        body+=f'''<div class="grid"><div class="card"><h3>Совместные упоминания (непроверенные связи)</h3><ul>{co_rows or '<li>Нет данных</li>'}</ul><small>Упоминание вместе НЕ означает договорных отношений или общей атаки.</small></div><div class="card"><h3>Сходство по стране / отрасли</h3><ul>{peer_rows or '<li>Нет данных</li>'}</ul><small>Это кандидаты для дальнейшего анализа, не связи в графе доказанных отношений.</small></div></div>''' 
    elif selected:
        body+='<p>Организация не найдена при выбранных фильтрах.</p>'
    else:
        body+='<div class="card"><h2>Как увидеть ветви графа</h2><p>Сначала выбери организацию выше. Связи формируются из подтверждённых отношений с URL и совместных упоминаний в сохранённых статьях. Если у выбранной организации их нет, показан честный пустой граф и форма добавления проверяемого отношения.</p></div>'
    return page('Граф связей',body+'<p class="note">Общие страна и отрасль — не деловые отношения. Сообщение о пострадавшем соседе — не доказательство атаки на эту организацию.</p>')


def method_page() -> bytes:
    return page("Методология", """<div class="page-heading"><div><p class="eyebrow">Модель v6</p><h1>Как рассчитывается приоритет</h1><p class="lead">Прозрачный индекс 0–100 для сортировки организаций по наблюдаемым сигналам.</p></div></div>
    <div class="note"><b>Индекс не является вероятностью будущего взлома.</b> Для такого прогноза нужна размеченная история наблюдений и исходов, проверка на новых данных и калибровка. Текущая модель — объяснимая эвристика.</div>
    <div class="grid"><section class="card"><h2>01 · Прямые сигналы — до 75 баллов</h2><p>Окно наблюдения — последние 30 дней. Базовый вклад прямой угрозы — 55, сообщения об инциденте — 35, заявления об атаке — 28. Угрозы и заявления имеют период полураспада 7 дней, сообщения об инцидентах — 10 дней.</p><p>Самый сильный уникальный сигнал учитывается полностью. Второй — с коэффициентом 0,45, третий — 0,45² и далее. Сумма ограничена 75 баллами. Перепечатки одной истории объединяются и не делают событие новее. Оспариваемые сведения ослабляются, отклонённые и синтетические записи исключаются.</p><p>Заявление о совершённой атаке показывает наблюдаемую активность, но не доказывает следующий инцидент.</p></section><section class="card"><h2>02 · Связи — до 15 баллов</h2><p>Используются только проверенные документированные отношения с источником и датой проверки: материнские и дочерние компании, поставщики, клиенты, партнёры и другие документированные связи.</p><p>Активный сигнал у связанной организации даёт ограниченный контекст: 15% её прямого индекса, максимум 8 баллов на соседа и 15 баллов суммарно. Повторные ссылки на одного соседа не увеличивают вклад.</p><p>Совместное упоминание, сходство названий и неподтверждённые предложения отношений не дают баллов за связи.</p></section></div>
    <section class="card"><h2>03 · Отраслевой фон — до 10 баллов</h2><p>Свежие сигналы у других наблюдаемых организаций той же отрасли дают 6% их прямого индекса, максимум 3 балла на организацию и 10 суммарно. Организация, уже учтённая через подтверждённую связь, повторно не считается. Общая отрасль не создаёт отношение в графе.</p><p>Если прямых сигналов нет, но есть косвенный фон, карточка помечена «Только контекст». Это помогает отличить фон от сообщений непосредственно об организации.</p></section>
    <div class="grid"><section class="card"><h2>Качество данных — отдельно от балла</h2><p>Число независимых групп источников и ручная проверка публикаций характеризуют опору на данные, но не повышают риск. Проверка публикации не означает подтверждённый взлом. Состояние сборщиков показывается отдельно: сбора ещё не было, данные устарели, есть ошибки или последние проверки успешны.</p><p><b>Нет сигналов — не нулевой риск.</b> Если нет пригодных сведений, индекс отображается как «—». Успешная проверка источника не гарантирует полного охвата.</p></section><section class="card"><h2>Уровни приоритета</h2><table><tr><th>Индекс</th><th>Приоритет</th></tr><tr><td>1–24</td><td>Низкий</td></tr><tr><td>25–49</td><td>Повышенный</td></tr><tr><td>50–74</td><td>Высокий</td></tr><tr><td>75–100</td><td>Критический</td></tr><tr><td>—</td><td>Нет достаточных сигналов</td></tr></table></section></div>
    <section class="card"><h2>Источники и ограничения</h2><p>Программа читает публичные RSS, API и разрешённые открытые страницы. Сначала собирает публикации, затем сопоставляет организации и предлагает кандидатов для проверки. Сохраняет первоисточник, даты и происхождение сведений. ИИ факультативен и по умолчанию выключен.</p><p>Охват неполон, новости запаздывают, классификация и объединение событий могут ошибаться. Исторические модели остаются исследовательскими. Предыдущий индекс 0–40 сохранён для совместимости исторических данных и старого API; новый обзор, карточки и экспорт риска используют модель v6 и диапазон 0–100.</p><p><a href="/api/risks">JSON API новой модели</a> · <a href="/export/risks">Экспорт CSV</a></p></section>""")


def make_handler(db_path,controller=None,*,instance_id=None):
    from .web_actions import ActionsMixin
    csrf=secrets.token_urlsafe(32)
    instance_id=instance_id or secrets.token_urlsafe(18)
    class Handler(ActionsMixin,BaseHTTPRequestHandler):
        _csrf=csrf
        _controller=controller
        _db_path=db_path
        def do_GET(self):
            if not self._local_request():
                self.send_error(403,'Local only');return
            parsed = urlsplit(self.path)
            con = sqlite3.connect(str(db_path),timeout=15)
            con.row_factory = sqlite3.Row
            collecting=False
            try:
                if parsed.path == "/api/runtime":
                    from .runtime import runtime_info
                    content=json.dumps(runtime_info(db_path,instance_id=instance_id),ensure_ascii=False).encode();mime="application/json; charset=utf-8";status=200
                elif parsed.path == "/about":
                    content=about_page(db_path,instance_id=instance_id);mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/" or parsed.path == '/launch/'+instance_id:
                    collecting=bool(controller and controller.status().get('busy'))
                    content=home(con,parse_qs(parsed.query),collecting=collecting); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/analytics":
                    content=analytics_page(con);mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/api/analytics":
                    from .analytics import aggregate
                    content=json.dumps(aggregate(con),ensure_ascii=False).encode();mime="application/json; charset=utf-8";status=200
                elif parsed.path == "/incidents":
                    content=incidents_page(con,parse_qs(parsed.query));mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/events":
                    content=events_page(con,parse_qs(parsed.query)); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/candidates":
                    content=candidates_page(con,parse_qs(parsed.query)); mime="text/html; charset=utf-8"; status=200
                elif parsed.path.startswith('/candidate/'):
                    tail=parsed.path.rsplit('/',1)[-1]
                    content=candidate_page(con,int(tail),csrf=csrf) if tail.isdigit() else None
                    status=200 if content else 404
                    content=content or page('404','<h1>Кандидат не найден</h1>');mime="text/html; charset=utf-8"
                elif parsed.path == "/api/candidates":
                    from .entity_graph import list_candidates
                    content=json.dumps(list_candidates(con,status='',limit=1000),ensure_ascii=False).encode()
                    mime="application/json; charset=utf-8";status=200
                elif parsed.path == "/discovery":
                    content=discovery_page(con); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/organizations":
                    from .admin_web import organizations_page
                    content=organizations_page(con,csrf,(parse_qs(parsed.query).get('message') or [''])[0]);mime="text/html; charset=utf-8";status=200
                elif parsed.path.startswith('/organizations/edit/'):
                    from .admin_web import edit_org_page
                    content=edit_org_page(con,parsed.path.split('/')[-1],csrf,(parse_qs(parsed.query).get('message') or [''])[0]);status=200 if content else 404
                    content=content or page('404','<h1>Неизвестная организация</h1>');mime="text/html; charset=utf-8"
                elif parsed.path == "/sources":
                    content=sources_page(con,csrf,(parse_qs(parsed.query).get('message') or [''])[0]); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/quality":
                    content=quality_page(con);mime="text/html; charset=utf-8";status=200
                elif parsed.path.startswith('/export/'):
                    kind=parsed.path.rsplit('/',1)[-1]
                    if kind not in ('scores','entities','evidence','risks'):
                        content=b'Not found';status=404;mime='text/plain; charset=utf-8'
                    else:
                        buf=io.StringIO()
                        writer=csv.writer(buf)
                        if kind=='risks':
                            from .scoring import assess_all
                            orgs={r['id']:r for r in con.execute('SELECT id,name,country,sector FROM organizations')}
                            fields=['id','name','country','sector','score','score_max','level','status','direct_score','related_score','sector_score','model_version']
                            rows=[dict(r,id=r['org_id'],name=orgs[r['org_id']]['name'],country=orgs[r['org_id']]['country'],sector=orgs[r['org_id']]['sector']) for r in assess_all(con)]
                        elif kind=='scores':
                            fields=['id','name','country','sector','score','completeness','status']
                            rows=latest_scores(con)
                        elif kind=='entities':
                            fields=['id','name','country','sector','status','first_seen','last_seen']
                            rows=con.execute('SELECT * FROM entity_candidates ORDER BY last_seen DESC LIMIT 30000').fetchall()
                        else:
                            fields=['id','title','url','published_at','kind','review_status']
                            rows=con.execute('SELECT * FROM items ORDER BY published_at DESC LIMIT 30000').fetchall()
                        writer.writerow(fields)
                        for row in rows:
                            writer.writerow([csv_safe(row[x]) for x in fields])
                        content=('\ufeff'+buf.getvalue()).encode('utf-8')
                        mime='text/csv; charset=utf-8';status=200
                elif parsed.path == "/control":
                    from .web_controls import control_page
                    content=control_page(controller,csrf,(parse_qs(parsed.query).get('message') or [''])[0]);mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/audit":
                    from .web_controls import audit_page
                    content=audit_page(con,csrf,(parse_qs(parsed.query).get('message') or [''])[0]);mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/graph":
                    content=graph_page(con,parse_qs(parsed.query),csrf);mime="text/html; charset=utf-8";status=200
                elif parsed.path == "/api/graph":
                    from .graph_temporal import graph_context_at
                    import datetime as dt
                    q=parse_qs(parsed.query)
                    org=(q.get('org_id') or [''])[0]
                    d=(q.get('as_of') or [dt.datetime.now(dt.timezone.utc).date().isoformat()])[0]
                    try:
                        data=graph_context_at(con,org,dt.date.fromisoformat(d))
                        content=json.dumps(data,ensure_ascii=False).encode();status=200
                    except (ValueError,TypeError):
                        content=b'{"error":"Invalid organization or date"}';status=400
                    mime="application/json; charset=utf-8"
                elif parsed.path == "/research":
                    content=research_page(con); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/cybermap":
                    content=cybermap_page(con); mime="text/html; charset=utf-8"; status=200
                elif parsed.path == "/api/cybermap":
                    from .cybermap import recent_observations
                    content=json.dumps(recent_observations(con),ensure_ascii=False).encode()
                    mime="application/json; charset=utf-8"; status=200
                elif parsed.path.startswith('/api/org/') and parsed.path.endswith('/brief'):
                    org_id=parsed.path.split('/')[3]
                    try:
                        content=json.dumps(local_brief(con,org_id),ensure_ascii=False).encode()
                        status=200
                    except ValueError:
                        content=b'{"error":"Unknown organization"}';status=404
                    mime="application/json; charset=utf-8"
                elif parsed.path == "/method":
                    content=method_page(); mime="text/html; charset=utf-8"; status=200
                elif parsed.path.startswith("/org/"):
                    from urllib.parse import unquote
                    content=org_page(con,unquote(parsed.path.split("/",2)[-1])); status=200 if content else 404
                    content=content or page("Не найдено","<h1>Неизвестная организация</h1>");mime="text/html; charset=utf-8"
                elif parsed.path == "/api/risks":
                    from .scoring import assess_all
                    content=json.dumps(assess_all(con),ensure_ascii=False).encode()
                    mime="application/json; charset=utf-8";status=200
                elif parsed.path.startswith('/api/org/') and parsed.path.endswith('/risk'):
                    from .scoring import assess_risk
                    from urllib.parse import unquote
                    org_id=unquote(parsed.path.split('/')[3])
                    try:
                        data=assess_risk(con,org_id)
                        content=json.dumps(data,ensure_ascii=False).encode();status=200
                    except ValueError:
                        content=b'{"error":"Unknown organization"}';status=404
                    mime="application/json; charset=utf-8"
                elif parsed.path == "/api/organizations":
                    rows=latest_scores(con)
                    content=json.dumps([{"id":r["id"],"name":r["name"],"sector":r["sector"],"country":r["country"],"score":r["score"],"coverage":r["completeness"],"status":r["status"]} for r in rows],ensure_ascii=False).encode()
                    mime="application/json; charset=utf-8"; status=200
                else:
                    content=page("404","<h1>Страница не найдена</h1>");mime="text/html; charset=utf-8";status=404
                self.send_response(status)
                self.send_header("Content-Type",mime)
                self.send_header("Content-Length",str(len(content)))
                if parsed.path.startswith('/export/') and status==200:
                    self.send_header('Content-Disposition','attachment; filename="threatwatch-'+parsed.path.rsplit('/',1)[-1]+'.csv"')
                self.send_header("X-Content-Type-Options","nosniff")
                self.send_header("Content-Security-Policy","default-src 'none'; style-src 'unsafe-inline'; frame-src https://cybermap.kaspersky.com; base-uri 'none'; form-action 'self'")
                self.send_header("Cache-Control","no-store")
                from . import __version__
                self.send_header('X-ThreatWatch-Version',__version__)
                self.send_header('X-ThreatWatch-Instance',instance_id)
                if collecting:
                    self.send_header('Refresh','8')
                self.end_headers()
                self.wfile.write(content)
            finally:
                con.close()
    return Handler


def about_page(db_path,*,instance_id=None):
    from .runtime import runtime_info
    info=runtime_info(db_path,instance_id=instance_id)
    fields=[('Версия','version'),('Сборка','build'),('Папка приложения','source_dir'),
            ('Файл базы данных','database_path'),('Python','python_executable'),('Шкала приоритета','risk_scale')]
    if instance_id:fields.append(('Идентификатор запуска','instance_id'))
    rows=''.join(f'<tr><th>{label}</th><td><code>{esc(info[key])}</code></td></tr>' for label,key in fields)
    return page('О приложении',f'''<div class="page-heading"><div><p class="eyebrow">Запущенная копия</p><h1>ThreatWatch Global {esc(info['version'])}</h1><p class="lead">Здесь видны версия и папка приложения, которое обслуживает эту вкладку.</p></div></div>
    <section class="card"><table>{rows}</table></section><div class="note">Если после распаковки открывается прежний интерфейс, проверьте версию здесь и адрес, напечатанный в новом окне запуска. В режиме desktop адрес выбирается заново при каждом запуске. Открывайте полный адрес VERIFIED dashboard с идентификатором запуска, а не старую закладку.</div><p><a href="/">Открыть новый обзор →</a></p>''')


def serve(db_path,host="127.0.0.1",port=8765,controller=None,open_browser=False):
    if host not in {"127.0.0.1","localhost","::1"}:
        raise ValueError("The dashboard is local-only; bind to 127.0.0.1")
    from .control import CollectionController
    controller=controller or CollectionController(db_path)
    instance_id=secrets.token_urlsafe(18)
    server=bind_dashboard(db_path,controller,host,port,desktop=open_browser,instance_id=instance_id)
    port=server.server_address[1]
    from .runtime import runtime_info
    info=runtime_info(db_path)
    print(f"ThreatWatch Global {info['version']} | build {info['build']}")
    print(f"Application folder: {info['source_dir']}")
    print(f"Database: {info['database_path']}")
    base_url=f'http://{host}:{port}'
    launch_url=base_url+'/launch/'+instance_id
    worker=None
    if open_browser:
        from .startup import verify_server
        import webbrowser
        worker=threading.Thread(target=server.serve_forever,kwargs={'poll_interval':.2},daemon=True,name='threatwatch-http')
        worker.start()
    try:
        if open_browser:
            verify_server(base_url,instance_id=instance_id,version=info['version'])
            print(f"VERIFIED dashboard: {launch_url}",flush=True)
            print(f"Launch ID: {instance_id}",flush=True)
            controller.schedule()
            controller.run_now()
            webbrowser.open(launch_url)
            worker.join()
        else:
            print(f"Dashboard: {base_url} (Ctrl+C to stop)",flush=True)
            server.serve_forever(poll_interval=.4)
    except KeyboardInterrupt:
        pass
    finally:
        controller.shutdown()
        if worker:
            server.shutdown()
            worker.join(timeout=5)
        server.server_close()


def bind_dashboard(db_path,controller,host,port,*,desktop=False,instance_id=None):
    """Never attach to or terminate another installation already using the port."""
    import errno
    from .startup import ExclusiveLocalHTTPServer
    if not isinstance(port,int) or not 0<=port<=65535:
        raise ValueError('Port must be between 0 and 65535')
    attempts=10 if desktop and port else 1
    for candidate in range(port,min(65536,port+attempts)):
        try:
            server=ExclusiveLocalHTTPServer((host,candidate),make_handler(db_path,controller,instance_id=instance_id))
        except OSError as exc:
            if not desktop or (exc.errno!=errno.EADDRINUSE and getattr(exc,'winerror',None) not in {10048,10013}):
                raise
            continue
        if candidate!=port:
            print(f"Port {port} is already in use. This installation will open on port {candidate}; the other process stays running.")
        return server
    raise OSError(errno.EADDRINUSE,'No free dashboard port in the selected range')
