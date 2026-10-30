"""Workspace regressions: filtering, provenance, risk API and CSV consistency."""
import csv
import datetime as dt
import http.client
import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from threatwatch.config import Organization
from threatwatch.dashboard import home, org_page, make_handler, method_page, graph_page
from threatwatch.registry import activate
from threatwatch.scoring import assess_risk
from threatwatch.store import connect, upsert_organizations, add_item


class WorkspaceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=Path(self.tmp.name)/'ui.db'
        self.con=connect(self.db)
        upsert_organizations(self.con,[Organization('alpha','Альфа <Банк>','finance','RU',('Альфа',)),Organization('beta','Beta Example','technology','US',('Beta',))])

    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def signal(self):
        add_item(self.con,url='https://example.test/news',title='Альфа <script>alert(1)</script> threat',summary='Public threat',source_name='Editorial',published_at=dt.datetime.now(dt.timezone.utc).isoformat(),kind='threat_statement',confidence=.8,rationale='Headline',org_ids=['alpha'])

    def test_running_version_visible_and_links_to_diagnostics(self):
        from threatwatch import __version__
        content=home(self.con).decode()
        self.assertIn(f'ThreatWatch v{__version__}',content)
        self.assertIn('href="/about"',content)
        self.assertIn(f'aria-label="О приложении, версия {__version__}"',content)

    def test_empty_database_explains_new_workflow_without_fake_signals(self):
        content=home(self.con).decode()
        self.assertIn('Новая рабочая панель ThreatWatch 6',content)
        self.assertIn('Индекс 0–100 с объяснением каждого вклада',content)
        self.assertIn('публикаций в базе нет',content)
        self.assertIn('href="/organizations"',content)
        self.assertIn('href="/control"',content)
        self.assertIn('href="/graph"',content)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM items').fetchone()[0],0)
        self.signal()
        self.assertNotIn('id="first-run-title"',home(self.con).decode())

    def test_black_violet_workspace_and_operational_hero(self):
        content=home(self.con).decode()
        self.assertIn('--bg:#09090d',content)
        self.assertIn('--accent:#a67cff',content)
        self.assertIn('radial-gradient',content)
        self.assertIn('Сигналы сегодня.',content)
        self.assertIn('Риски — в фокусе.',content)
        self.assertIn('class="card intro-panel"',content)
        self.assertNotIn('#09111d',content)
        self.assertNotIn('#5cccd5',content)
        detail=org_page(self.con,'alpha').decode()
        self.assertIn('--bg:#09090d',detail)
        self.assertIn('--accent:#a67cff',detail)

    def test_filters_escape_and_unknown_is_not_zero(self):
        content=home(self.con,{'q':['альфа']}).decode()
        self.assertIn('Альфа &lt;Банк&gt;',content)
        self.assertNotIn('Beta Example',content)
        self.assertIn('Недостаточно данных',content)
        self.assertIn('Сбор ещё не запускался',content)
        self.assertNotIn('width:0%',content)
        self.assertIn('Нет организаций с такими фильтрами',home(self.con,{'country':['IT']}).decode())

    def test_paused_organizations_hidden_and_unknown_at_end(self):
        self.signal()
        content=home(self.con).decode()
        self.assertLess(content.index('Альфа &lt;Банк&gt;'),content.index('Beta Example'))
        activate(self.con,'alpha',False)
        self.assertNotIn('Альфа &lt;Банк&gt;',home(self.con).decode())

    def test_detail_uses_same_score_with_safe_provenance(self):
        self.signal()
        risk=assess_risk(self.con,'alpha')
        content=org_page(self.con,'alpha').decode()
        self.assertIn(f'<strong>{risk["score"]}</strong>',content)
        self.assertIn('https://example.test/news',content)
        self.assertIn('&lt;script&gt;',content)
        self.assertNotIn('<script>',content)
        self.assertIn('Прямые сигналы',content)
        self.assertIn('Документированные отношения',content)
        self.assertIn('Упомянуты вместе',content)
        self.assertIsNone(org_page(self.con,'absent'))

    def test_pagination_preserves_filters_and_caps_visible_rows(self):
        upsert_organizations(self.con,[Organization(f'item-{i}',f'Extra {i:02d}','technology','US',(f'Extra {i:02d}',)) for i in range(20)])
        first=home(self.con,{'q':['Extra']}).decode()
        second=home(self.con,{'q':['Extra'],'page':['2']}).decode()
        self.assertIn('Extra 00</strong>',first)
        self.assertNotIn('Extra 15</strong>',first)
        self.assertIn('q=Extra&amp;page=2',first)
        self.assertIn('Показано 15 из 20',first)
        self.assertIn('Extra 15</strong>',second)
        self.assertNotIn('Extra 00</strong>',second)
        self.assertIn('Показано 5 из 20',second)
        self.assertIn('Страница 1 из 2',home(self.con,{'q':['Extra'],'page':['invalid']}).decode())

    def test_graph_defaults_to_an_existing_connection(self):
        now=dt.datetime.now(dt.timezone.utc).isoformat()
        self.con.execute("INSERT INTO organization_relations(source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at) VALUES(?,?,?,?,?,?)",('alpha','beta','parent','https://example.test/ownership','unverified',now))
        self.signal()
        self.con.execute("INSERT INTO relation_suggestion_evidence(relation_id,item_id,excerpt,detection_method) SELECT r.id,i.id,?,'test' FROM organization_relations r CROSS JOIN items i", ('Alpha is a subsidiary of <script>Beta</script>',))
        self.con.commit()
        content=graph_page(self.con,{}).decode()
        self.assertIn('https://example.test/ownership',content)
        self.assertIn('Отношения и ссылки',content)
        self.assertIn('&lt;script&gt;Beta&lt;/script&gt;',content)
        self.assertNotIn('<script>',content)
        self.assertIn('Дочерняя компания',org_page(self.con,'beta').decode())

    def test_method_describes_current_model(self):
        content=method_page().decode()
        self.assertIn('0–100',content)
        self.assertIn('75 баллов',content)
        self.assertIn('0,45',content)
        self.assertIn('Нет сигналов',content)

    def test_api_export_and_pages_over_http(self):
        self.signal()
        self.con.commit()
        server=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.db))
        worker=threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        def get(path):
            connection=http.client.HTTPConnection('127.0.0.1',server.server_port,timeout=5)
            connection.request('GET',path)
            response=connection.getresponse()
            body=response.read()
            status=response.status
            connection.close()
            return status,body
        try:
            status,body=get('/api/risks')
            self.assertEqual(status,200)
            all_risks=json.loads(body)
            expected=next(r for r in all_risks if r['org_id']=='alpha')
            status,body=get('/api/org/alpha/risk')
            self.assertEqual(status,200)
            self.assertEqual(json.loads(body)['score'],expected['score'])
            self.assertEqual(get('/api/org/absent/risk')[0],404)
            status,body=get('/export/risks')
            self.assertEqual(status,200)
            exported=list(csv.DictReader(io.StringIO(body.decode('utf-8-sig'))))
            alpha=next(r for r in exported if r['id']=='alpha')
            self.assertEqual(int(alpha['score']),expected['score'])
            self.assertEqual(alpha['score_max'],'100')
            for path in ['/', '/org/alpha','/method','/api/organizations']:
                self.assertEqual(get(path)[0],200,path)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(5)


if __name__=='__main__':unittest.main()
