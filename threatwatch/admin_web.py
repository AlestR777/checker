"""Organization registry and region-aware source controls for localhost dashboard."""
from __future__ import annotations
from .registry import all_sources,aliases,has_active


def organizations_page(con, csrf, notice=''):
    from .dashboard import page,esc
    counts={r['org_id']:r['n'] for r in con.execute('SELECT org_id,COUNT(*) n FROM mentions GROUP BY org_id')}
    rows=con.execute('''SELECT o.*, COALESCE(p.active,1) active FROM organizations o
      LEFT JOIN organization_preferences p ON p.org_id=o.id ORDER BY active DESC, o.country, o.name''').fetchall()
    trs=''
    for r in rows:
        action=('Остановить отслеживание' if r['active'] else 'Восстановить')
        target=('archive' if r['active'] else 'restore')
        trs+=(f'<tr><td><a href="/org/{esc(r["id"])}"><b>{esc(r["name"])}</b></a></td>'
              f'<td>{esc(r["country"])}</td><td>{esc(r["sector"])}</td>'
              f'<td>{counts.get(r["id"],0)}</td><td>{"Отслеживается" if r["active"] else "В архиве"}</td>'
              f'<td><a href="/organizations/edit/{esc(r["id"])}">Редактировать</a>'
              f'<form method="post" action="/organizations/{target}/{esc(r["id"])}" class="inline-form">'
              f'<input type="hidden" name="csrf" value="{esc(csrf)}"><button class="secondary">{action}</button></form></td></tr>')
    body=f'''<h1>Организации</h1><p class="lead">Здесь управляется список мониторинга. Удаление — обратимая архивация, публикации и история оценок сохраняются.</p>
    {f'<div class="note">{esc(notice)}</div>' if notice else ''}
    <div class="card"><h2>Добавить организацию</h2><form method="post" action="/organizations/add">
    <input type="hidden" name="csrf" value="{esc(csrf)}">
    <label>Название <input name="name" required maxlength="130" placeholder="Название компании"></label>
    <label>Страна ISO-2 <input name="country" required maxlength="2" placeholder="DE"></label>
    <label>Отрасль <input name="sector" required maxlength="100" placeholder="Transport"></label>
    <label>Варианты названия через | <input name="aliases" maxlength="1400" placeholder="Acme Ltd | Acme Group"></label>
    <label>Комментарий <input name="notes" maxlength="1200" placeholder="Необязательно"></label>
    <button type="submit">Добавить в мониторинг</button></form></div>
    <div class="card" style="overflow-x:auto"><h2>Список ({len(rows)})</h2><table>
    <tr><th>Организация</th><th>Страна</th><th>Сектор</th><th>Публикации</th><th>Статус</th><th>Управление</th></tr>{trs}</table></div>
    <p class="muted">Ручное добавление не подтверждает инцидент. После изменения алиасов каталог можно повторно сопоставить через раздел «Управление».</p>'''
    return page('Организации',body)


def edit_org_page(con,org_id,csrf,notice=''):
    from .dashboard import page,esc
    row=con.execute('SELECT * FROM organizations WHERE id=?',(org_id,)).fetchone()
    if not row:return None
    alias=' | '.join(aliases(con,org_id))
    return page('Редактировать организацию',f'''<p><a href="/organizations">← Организации</a></p><h1>Редактировать: {esc(row['name'])}</h1>
       {f'<div class="note">{esc(notice)}</div>' if notice else ''}
       <div class="card"><form method="post" action="/organizations/edit/{esc(org_id)}">
       <input type="hidden" name="csrf" value="{esc(csrf)}">
       <label>Название <input name="name" value="{esc(row['name'])}" required maxlength="130"></label>
       <label>Страна <input name="country" value="{esc(row['country'])}" required maxlength="2"></label>
       <label>Отрасль <input name="sector" value="{esc(row['sector'])}" required maxlength="100"></label>
       <label>Дополнительные названия через | <input name="aliases" value="{esc(alias)}" maxlength="1400"></label>
       <label>Описание <input name="notes" value="{esc(row['notes'])}" maxlength="1200"></label>
       <button>Сохранить</button></form></div>
       <p class="muted">Редактирование не переоценивает старые публикации как новые. Исторические записи сохраняются.</p>''')


def sources_settings_page(con,csrf,notice=''):
    from .dashboard import page,esc
    sources=all_sources(con)
    counts={r['source_name']:dict(r) for r in con.execute('''SELECT source_name,MAX(checked_at) checked_at,
        SUM(CASE WHEN status='ok' THEN 1 ELSE 0 END) ok,
        SUM(CASE WHEN status='error' THEN 1 ELSE 0 END) bad
        FROM source_checks GROUP BY source_name''')}
    body='<h1>Источники и регионы</h1><p class="lead">Источники можно включать по отдельности или группами. Французские не удалены — они просто отключены в глобальном профиле. Выбор региона источника не ограничивает географию жертв.</p>'
    if notice:body+=f'<div class="note">{esc(notice)}</div>'
    for scope,label in [('GLOBAL','Международные'),('EU','Европа'),('FR','Франция'),('US','США'),('GB','Великобритания'),('DE','Германия'),('IT','Италия'),('ES','Испания'),('PL','Польша'),('NL','Нидерланды')]:
        records=[s for s in sources if s['scope']==scope]
        if not records:continue
        body+=f'<div class="card"><h2>{label} · активно {sum(s["enabled"] for s in records)} / {len(records)}</h2>'
        for enabled,title in [(True,'Включить группу'),(False,'Выключить группу')]:
            body+=f'''<form class="inline-form" method="post" action="/sources/bulk"><input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="scope" value="{scope}"><input type="hidden" name="enabled" value="{int(enabled)}"><button class="secondary">{title}</button></form>'''
        body+='<div style="overflow-x:auto"><table><tr><th>Источник</th><th>Тип</th><th>Состояние</th><th>Последний запрос</th><th>Успех / ошибки</th><th></th></tr>'
        for s in records:
            stat=counts.get(s['name'],{})
            body+=f'''<tr><td><strong>{esc(s['name'])}</strong></td><td>{esc(s['type'])}</td><td>{'Включён' if s['enabled'] else 'Выключен'}</td>
            <td>{esc(stat.get('checked_at') or '—')}</td><td>{int(stat.get('ok') or 0)} / {int(stat.get('bad') or 0)}</td>
            <td><form class="inline-form" method="post" action="/sources/toggle">
            <input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="source_id" value="{esc(s['id'])}">
            <input type="hidden" name="enabled" value="{int(not s['enabled'])}"><button class="secondary">{'Отключить' if s['enabled'] else 'Включить'}</button></form></td></tr>'''
        body+='</table></div></div>'
    # Keep historical source checks visible, even for removed or renamed configs.
    configured={s['name'] for s in sources}
    legacy=[r for r in con.execute('SELECT source_name,MAX(checked_at) AS checked_at FROM source_checks GROUP BY source_name') if r['source_name'] not in configured]
    if legacy:
        body+='<div class="card"><h2>Исторические или неизвестные источники</h2><ul>'
        body+=''.join(f'<li>{esc(r["source_name"])} · {esc(r["checked_at"])}</li>' for r in legacy)
        body+='</ul></div>'
    body+='<div class="note">Ошибка TLS/403/429 обычно относится к конкретному источнику или сети. Проверка сертификатов остаётся включённой. Отключение проблемного источника не удаляет ранее собранные записи.</div>'
    return page('Источники',body)


def relation_editor(con,org_id,csrf):
    from .dashboard import esc
    rows=con.execute('SELECT id,name,country FROM organizations WHERE id!=? ORDER BY country,name LIMIT 2000',(org_id,)).fetchall()
    opts=''.join(f'<option value="{esc(r["id"])}">{esc(r["name"])} ({esc(r["country"])})</option>' for r in rows)
    return f'''<div class="card"><h2>Добавить подтверждаемую связь</h2>
      <p class="muted">Используй только документированные отношения с публичной ссылкой. Совместное упоминание — не деловая связь.</p>
      <form method="post" action="/relations/add">
      <input type="hidden" name="csrf" value="{esc(csrf)}"><input type="hidden" name="source_org_id" value="{esc(org_id)}">
      <label>С кем <select name="target_org_id" required>{opts}</select></label>
      <label>Отношение <select name="relation_type"><option value="supplier">Поставщик</option><option value="customer">Клиент</option><option value="parent">Материнская организация</option><option value="subsidiary">Дочерняя</option><option value="partner">Партнёр</option><option value="same_group">Одна группа</option><option value="other_documented">Другое документированное</option></select></label>
      <label>Публичный источник HTTPS <input name="evidence_url" type="url" required placeholder="https://..."></label>
      <button>Сохранить для проверки</button></form></div>'''
