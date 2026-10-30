"""Web templates for strictly-local browser controls, no arbitrary command execution."""
from __future__ import annotations
from .audit_web import progress,pending,evaluate
from .control import CollectionController


def form(action,csrf,label,extra=''):
    from .dashboard import esc
    return (f'<form method="post" action="{esc(action)}"><input type="hidden" name="csrf" '
            f'value="{esc(csrf)}">{extra}<button type="submit">{esc(label)}</button></form>')


def control_page(controller,csrf,notice=''):
    from .dashboard import page,esc
    s=controller.status()
    result=s['result'] or {}
    err=result.get('errors',[]) if isinstance(result,dict) else []
    body='<h1>Управление</h1><p class="lead">Сбор выполняется в отдельном потоке. ИИ выключен по умолчанию.</p>'
    if notice:body+=f'<div class="note">{esc(notice)}</div>'
    body+='<div class="grid"><div class="card"><h2>Состояние</h2>'
    body+=f'<p><b>{"Идёт сбор" if s["busy"] else "Ожидание"}</b></p>'
    body+=f'<p>{esc(s["message"])}</p>'
    body+=f'<p>Расписание: {"ВКЛ" if s["scheduled"] else "ВЫКЛ"}</p>'
    for label,key in [('Начало','started'),('Последнее завершение','finished'),('Следующий запуск','next_run')]:
        body+=f'<p>{label}: {esc(s[key] or "—")}</p>'
    body+='</div><div class="card"><h2>Действия</h2>'
    body+=form('/control/run',csrf,'Собрать сейчас')
    body+=form('/control/schedule',csrf,'Включить расписание: каждые 6 часов')
    body+=form('/control/stop',csrf,'Выключить расписание')
    body+=form('/control/discover',csrf,'Повторно распознать организации в базе')
    body+=form('/control/recompute',csrf,'Пересчитать индексы')
    body+='<p class="muted">Выполняющийся сбор не прерывается. Для выхода закрой окно приложения.</p></div></div>'
    if s['error']:body+=f'<div class="note">Ошибка: {esc(s["error"])}</div>'
    if result:
        body+='<div class="card"><h2>Последний результат</h2><table>'
        keys=('checked','fetched','matched','inserted','catalogued_unmatched','new_candidate_evidence','pending_candidates','skipped_rate_limited_sources')
        for key in keys:
            if key in result:body+=f'<tr><td>{esc(key)}</td><td>{esc(result[key])}</td></tr>'
        body+='</table>'
        if err:body+='<p>Нефатальные ошибки источников:</p><ul>'+''.join(f'<li>{esc(x)}</li>' for x in err[:15])+'</ul>'
        body+='</div>'
    body+='<p>Скачать данные: <a href="/export/risks">Приоритет 0–100 CSV</a> · <a href="/export/entities">Кандидаты CSV</a> · <a href="/export/evidence">Публикации CSV</a></p>'
    body+='<p class="muted">Страница обновляется каждые 8 секунд.</p><meta http-equiv="refresh" content="8;url=/control">'
    return page('Управление',body)


def audit_page(con,csrf,notice=''):
    from .dashboard import page,esc,safe_href
    stat=progress(con)
    body='<h1>Проверка распознавания организаций</h1><p class="lead">Сверяй каждую публикацию с оригиналом: автоматическая подсказка не является эталоном.</p>'
    if notice:body+=f'<div class="note">{esc(notice)}</div>'
    body+=f'<div class="card"><b>Проверено: {stat["reviewed"]} / {stat["total"]}</b>; осталось: {stat["remaining"]}</div>'
    if not stat['total']:
        body+='<div class="card">'+form('/audit/create',csrf,'Создать очередь из 80 публикаций')+'</div>'
    else:
        row=pending(con)
        if row:
            body+='<div class="card"><h2>'+esc(row['title'])+'</h2>'
            body+='<p>'+esc(row['summary'][:2000])+'</p>'
            body+=f'<p>{esc(row["source_name"])} · {esc(row["published_at"])}</p>'
            body+=f'<p><a href="{safe_href(row["url"])}" target="_blank" rel="noopener noreferrer">Открыть первоисточник</a></p>'
            body+=f'<p>Предложения модели (не подтверждены): <b>{esc(row["predicted"] or "нет")}</b></p>'
            body+=f'''<form method="post" action="/audit/save">
                <input type="hidden" name="csrf" value="{esc(csrf)}">
                <input type="hidden" name="url_key" value="{esc(row['url_key'])}">
                <label>Все действительно упомянутые организации через | (или NONE)<br>
                <input name="expected" required maxlength="1500" style="min-width: min(700px,90vw)" placeholder="Organization A|Organization B или NONE"></label>
                <label>Заметка <input name="notes" maxlength="800"></label>
                <button type="submit">Сохранить и далее</button></form></div>'''
        report=evaluate(con)
        body+=f'''<div class="card"><h2>Качество на проверенных материалах</h2>
            <p>Состояние: {esc(report.get('status'))}; проверено: {esc(report.get('reviewed_articles',0))}</p>
            <p>Precision: {esc(report.get('precision'))}; Recall: {esc(report.get('recall'))}; F1: {esc(report.get('f1'))}</p>
            <p class="muted">Нужно минимум 20 проверенных документов. Метрики измеряют извлечение названий, не вероятность взлома.</p></div>'''
    return page('Разметка',body)


def candidate_review_actions(con,candidate,csrf):
    from .dashboard import esc
    if not csrf or candidate['status']!='pending':return ''
    ident=int(candidate['id'])
    extra=f'''<label>Страна (ISO-2) <input name="country" required maxlength="2" value="{esc(candidate['country'])}"></label>
              <label>Отрасль <input name="sector" required maxlength="100" value="{esc(candidate['sector'])}"></label>'''
    return (f'<div class="card"><h2>Решение аналитика</h2><p>Проверь первоисточник до утверждения организации.</p>'
            +form(f'/candidate/{ident}/approve',csrf,'Добавить в мониторинг',extra)
            +form(f'/candidate/{ident}/reject',csrf,'Отклонить')+'</div>')
