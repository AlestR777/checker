"""POST handler mixin for local, CSRF-protected, allowlisted operations."""
from __future__ import annotations
from urllib.parse import parse_qs,urlsplit,quote

class ActionsMixin:
    def _local_request(self):
        host=(self.headers.get('Host') or '').lower().split(':')[0]
        return host in ('127.0.0.1','localhost') and self.client_address[0] in ('127.0.0.1','::1')

    def do_POST(self):
        if not self._local_request():self.send_error(403,'Local only');return
        origin=self.headers.get('Origin')
        if origin and urlsplit(origin).hostname not in ('127.0.0.1','localhost'):
            self.send_error(403,'Invalid origin');return
        if self.headers.get('Content-Type','').split(';')[0].strip()!='application/x-www-form-urlencoded':
            self.send_error(415,'Expected HTML form');return
        try:size=int(self.headers.get('Content-Length','0'))
        except ValueError:size=0
        if not 0<size<=8192:self.send_error(413,'Form too large or empty');return
        data=parse_qs(self.rfile.read(size).decode('utf-8','replace'))
        get=lambda key:(data.get(key) or [''])[0]
        if get('csrf')!=self._csrf:
            self.send_error(403,'CSRF token mismatch');return
        path=urlsplit(self.path).path
        con=None
        try:
            if path in ('/control/run','/control/schedule','/control/stop','/control/discover','/control/recompute'):
                if path=='/control/run':_,message=self._controller.run_now()
                elif path=='/control/schedule':_,message=self._controller.schedule()
                elif path=='/control/stop':_,message=self._controller.unschedule()
                else:
                    if self._controller.status()['busy']:
                        raise ValueError('Сначала дождись завершения текущего сбора')
                    from .store import connect
                    con=connect(self._db_path)
                    if path=='/control/discover':
                        from .entity_graph import discover_from_ledger
                        result=discover_from_ledger(con,limit=10000)
                        message='Кандидаты обновлены. Новых свидетельств: '+str(result['new_evidence'])
                    else:
                        from .scoring import recompute_all
                        from .store import latest_scores
                        ids=[r['id'] for r in latest_scores(con)]
                        recompute_all(con,ids)
                        message='Оценки обновлены для '+str(len(ids))+' организаций (без добавления недостоверных данных)'
                destination='/control'
            elif path == '/organizations/add' or path.startswith(('/organizations/archive/','/organizations/restore/','/organizations/edit/')):
                if self._controller.status()['busy']:
                    raise ValueError('Дождись завершения сбора перед изменением справочника')
                from .store import connect
                from .registry import manual_add,activate,change_details
                con=connect(self._db_path)
                if path=='/organizations/add':
                    ident=manual_add(con,name=get('name'),country=get('country'),sector=get('sector'),
                                   aliases=get('aliases'),notes=get('notes'))
                    message='Организация добавлена'
                else:
                    ident=path.rsplit('/',1)[-1]
                    if path.startswith('/organizations/archive/'):
                        activate(con,ident,False);message='Организация убрана из активного мониторинга, история сохранена'
                    elif path.startswith('/organizations/restore/'):
                        activate(con,ident,True);message='Организация восстановлена в мониторинге'
                    else:
                        change_details(con,ident,name=get('name'),country=get('country'),sector=get('sector'),
                                       aliases=get('aliases'),notes=get('notes'))
                        message='Карточка сохранена'
                if not path.startswith('/organizations/archive/'):
                    from .pipeline import reconcile_mentions
                    repaired=reconcile_mentions(con)
                    message+='; сохранённые публикации сопоставлены, новых связей: '+str(repaired['new_mentions'])
                destination='/organizations'
            elif path in ('/sources/toggle','/sources/bulk'):
                if self._controller.status()['busy']:
                    raise ValueError('Дождись завершения сбора перед изменением источников')
                from .store import connect
                from .registry import source_toggle,bulk_scope
                con=connect(self._db_path)
                enabled=get('enabled')=='1'
                if path.endswith('/toggle'):
                    source_toggle(con,get('source_id'),enabled)
                    message='Настройка источника сохранена'
                else:
                    n=bulk_scope(con,get('scope'),enabled)
                    message='Обновлено источников: '+str(n)
                destination='/sources'
            elif path.startswith('/relations/verify/'):
                from .normalize import utc_now
                if self._controller.status()['busy']:
                    raise ValueError('Дождись окончания сбора')
                from .store import connect
                con=connect(self._db_path)
                tail=path.rsplit('/',1)[-1]
                if not tail.isdigit():raise ValueError('Некорректный идентификатор')
                rel=con.execute('SELECT * FROM organization_relations WHERE id=?',(int(tail),)).fetchone()
                if not rel:raise ValueError('Связь не найдена')
                if not rel['evidence_url'].startswith('https://'):raise ValueError('Не найден публичный источник')
                con.execute("UPDATE organization_relations SET review_status='verified',verified_at=? WHERE id=?",(utc_now(),int(tail)))
                con.commit()
                message='Связь отмечена как проверенная аналитиком; это не свидетельство компрометации'
                destination='/graph?org_id='+quote(rel['source_org_id'])
            elif path=='/relations/add':
                if self._controller.status()['busy']:
                    raise ValueError('Изменения доступны после завершения сбора')
                from .store import connect
                from .entity_graph import RELATION_TYPES
                from .normalize import utc_now
                con=connect(self._db_path)
                src=get('source_org_id'); target=get('target_org_id');rel=get('relation_type');url=get('evidence_url').strip()
                if src==target or rel not in RELATION_TYPES:
                    raise ValueError('Недопустимое отношение')
                u=urlsplit(url)
                if len(url)>1500 or u.scheme!='https' or not u.hostname or u.username or u.password:
                    raise ValueError('Нужна публичная HTTPS-ссылка на источник')
                known=con.execute('SELECT COUNT(*) FROM organizations WHERE id IN (?,?)',(src,target)).fetchone()[0]
                if known!=2:raise ValueError('Одна из организаций отсутствует')
                con.execute('INSERT OR IGNORE INTO organization_relations '
                  '(source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at) '
                  'VALUES(?,?,?,?,?,?)',(src,target,rel,url,'unverified',utc_now()))
                con.commit()
                message='Связь сохранена как неподтверждённая, без изменения оценки'
                destination='/graph?org_id='+quote(src)
            elif path in ('/audit/create','/audit/save'):
                from .store import connect
                from .audit_web import generate,save
                con=connect(self._db_path)
                if path=='/audit/create':
                    result=generate(con)
                    message='Добавлено в очередь: '+str(result['added'])
                else:
                    save(con,get('url_key'),get('expected'),get('notes'))
                    message='Разметка сохранена'
                destination='/audit'
            elif path.startswith('/candidate/') and (path.endswith('/approve') or path.endswith('/reject')):
                from .store import connect
                from .entity_graph import approve_candidate,reject_candidate
                from .scoring import recompute_all
                parts=path.strip('/').split('/')
                if len(parts)!=3 or not parts[1].isdigit():raise ValueError('Invalid candidate')
                candidate_id=int(parts[1]);con=connect(self._db_path)
                if parts[2]=='reject':
                    reject_candidate(con,candidate_id)
                    message='Кандидат отклонён'
                else:
                    country=get('country').strip().upper();sector=get('sector').strip()
                    if len(country)!=2 or not country.isalpha():raise ValueError('Use ISO-2 country code')
                    if not (2<=len(sector)<=110):raise ValueError('Missing or invalid sector')
                    result=approve_candidate(con,candidate_id,country=country,sector=sector)
                    recompute_all(con,[result['organization_id']])
                    message='Организация добавлена; факт взлома этим не подтверждён'
                destination=f'/candidate/{candidate_id}'
            else:
                self.send_error(404,'Unknown action');return
        except (ValueError,KeyError) as exc:
            self.log_error('Invalid input: %s',str(exc)[:160]);self.send_error(400,'Invalid form data; check fields and source URL');return
        except Exception:
            self.log_error('Web action failed')
            self.send_error(500,'Internal action failed');return
        finally:
            if con is not None:con.close()
        self.send_response(303)
        self.send_header('Location',destination+('&' if '?' in destination else '?')+'message='+quote(message[:300]))
        self.send_header('Cache-Control','no-store')
        self.send_header('Content-Length','0')
        self.end_headers()
