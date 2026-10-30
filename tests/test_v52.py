"""v5.2: reversible entity management, source scopes, optional graph verification."""
import http.client
import re
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlencode

from threatwatch.config import Organization,load_organizations
from threatwatch.store import connect,upsert_organizations,latest_scores,add_item
from threatwatch.registry import (manual_add,change_details,activate,has_active,aliases,
                                  active_sources,all_sources,source_toggle,bulk_scope)
from threatwatch.entity_graph import runtime_organizations
from threatwatch.dashboard import make_handler,graph_page,page
from threatwatch.graph_render import relation_svg
from threatwatch.graph_temporal import graph_context_at
from threatwatch.control import CollectionController

class RegistryTests(unittest.TestCase):
    def setUp(self):
        t=tempfile.TemporaryDirectory();self.addCleanup(t.cleanup)
        self.db=Path(t.name)/'data.sqlite';self.con=connect(self.db);self.addCleanup(self.con.close)
        upsert_organizations(self.con,[Organization('org1','Example One','Energy','FR',('Example One',))])

    def test_sources_default_are_global_and_france_optional(self):
        definitions=all_sources(self.con)
        self.assertGreaterEqual(len(definitions),40)
        self.assertFalse(next(s for s in definitions if s['id']=='zataz-direct')['enabled'])
        self.assertTrue(next(s for s in definitions if s['id']=='the-hacker-news-global')['enabled'])
        self.assertFalse(next(s for s in definitions if s['id']=='gdelt-global-cyber')['enabled'])

    def test_source_override_persists(self):
        source_toggle(self.con,'zataz-direct',True)
        self.assertIn('zataz-direct',[s['id'] for s in active_sources(self.con)])
        con2=connect(self.db)
        try:self.assertTrue(next(s for s in all_sources(con2) if s['id']=='zataz-direct')['enabled'])
        finally:con2.close()
        source_toggle(self.con,'zataz-direct',False)
        self.assertNotIn('zataz-direct',[s['id'] for s in active_sources(self.con)])
        with self.assertRaises(ValueError):source_toggle(self.con,'not-a-source',True)

    def test_country_and_france_presets(self):
        self.assertEqual(bulk_scope(self.con,'DE',True),1)
        self.assertTrue(next(s for s in all_sources(self.con) if s['id']=='country-news-de')['enabled'])
        n=bulk_scope(self.con,'FR',True)
        self.assertGreater(n,5)
        self.assertTrue(next(s for s in all_sources(self.con) if s['id']=='cert-fr')['enabled'])
        bulk_scope(self.con,'FR',False)
        self.assertFalse(next(s for s in all_sources(self.con) if s['id']=='cert-fr')['enabled'])

    def test_manual_entity_persists_after_seed_import(self):
        oid=manual_add(self.con,name='Example Corporation',country='US',sector='Transport',aliases='Example Corp | ExCo')
        upsert_organizations(self.con,load_organizations())
        ids=[o.id for o in runtime_organizations(self.con,load_organizations())]
        self.assertIn(oid,ids)
        self.assertIn('ExCo',aliases(self.con,oid))
        self.assertIn(oid,[r['id'] for r in latest_scores(self.con)])
        with self.assertRaises(ValueError):manual_add(self.con,name='Example Corporation',country='US',sector='Transport')

    def test_archive_does_not_destroy_evidence_and_is_reversible(self):
        oid=manual_add(self.con,name='Example Corporation',country='US',sector='Transport')
        activate(self.con,oid,False)
        self.assertFalse(has_active(self.con,oid))
        self.assertNotIn(oid,[o.id for o in runtime_organizations(self.con,[])])
        self.assertNotIn(oid,[r['id'] for r in latest_scores(self.con)])
        self.assertTrue(self.con.execute('SELECT 1 FROM organizations WHERE id=?',(oid,)).fetchone())
        activate(self.con,oid,True)
        self.assertIn(oid,[o.id for o in runtime_organizations(self.con,[])])

    def test_manual_edits_not_reset_by_predefined_seed(self):
        change_details(self.con,'org1',name='Updated Example One',sector='Transport',country='DE',aliases='U Example | UE')
        upsert_organizations(self.con,[Organization('org1','Example One','Energy','FR',('Example One',))])
        rec=self.con.execute('SELECT * FROM organizations WHERE id=?',('org1',)).fetchone()
        self.assertEqual(rec['name'],'Updated Example One')
        self.assertEqual(rec['country'],'DE')
        self.assertIn('UE',runtime_organizations(self.con,[Organization('org1','Example One','Energy','FR',('Example One',))])[0].aliases)

    def test_graph_dashed_and_solid(self):
        nodes=[{'other_id':'org2','other_name':'Example Two','review_status':'verified'}]
        co=[{'id':'org3','name':'Example Three'}]
        svg=relation_svg('org1','Example One',nodes,co_mentions=co)
        self.assertIn('stroke-dasharray',svg)
        self.assertIn('Подтверждённая',svg)
        self.assertIn('Example Two',svg)
        self.assertIn('Example Three',svg)
        self.assertIn('Пока нет связей',relation_svg('org1','Example One',[]))

    def test_workspace_navigation(self):
        html=page('Test','<p>Hi</p>').decode()
        self.assertIn('--bg:#09090d',html)
        self.assertIn('class="sidebar"',html)
        self.assertIn('--accent:#a67cff',html)
        self.assertIn('Исследования и данные',html)
        self.assertIn('href="/organizations"',html)
        self.assertIn('href="/sources"',html)

class WebActionsTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory();self.addCleanup(tmp.cleanup)
        self.db=Path(tmp.name)/'ui.sqlite'
        con=connect(self.db)
        upsert_organizations(con,[Organization('one','Example One','Retail','FR',('Example One',)),
                                  Organization('two','Example Two','Retail','DE',('Example Two',))]);con.close()
        self.controller=CollectionController(self.db)
        self.srv=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.db,self.controller))
        self.thread=threading.Thread(target=self.srv.serve_forever,daemon=True);self.thread.start()
        self.addCleanup(self.stop)
        self.port=self.srv.server_address[1]
        status,body,_=self.req('GET','/organizations')
        self.assertEqual(status,200)
        self.csrf=re.search(r'name="csrf" value="([^"]+)"',body).group(1)

    def stop(self):
        self.controller.shutdown();self.srv.shutdown();self.srv.server_close();self.thread.join(timeout=3)

    def req(self,method,path,body=None):
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=4)
        if method=='POST':
            payload=urlencode({'csrf':self.csrf,**(body or {})})
            conn.request(method,path,body=payload,headers={'Content-Type':'application/x-www-form-urlencoded'})
        else:conn.request(method,path)
        r=conn.getresponse();data=r.read().decode('utf-8','replace');s=r.status;loc=r.getheader('Location');conn.close()
        return s,data,loc

    def test_org_management_via_web(self):
        s,body,_=self.req('GET','/organizations');self.assertEqual(s,200)
        self.assertIn('Добавить организацию',body)
        s,_,_=self.req('POST','/organizations/add',{'name':'Brand Alpha','country':'US','sector':'Retail','aliases':'Alpha'})
        self.assertEqual(s,303)
        c=connect(self.db)
        try:oid=c.execute('SELECT id FROM organizations WHERE name=?',('Brand Alpha',)).fetchone()['id']
        finally:c.close()
        self.assertEqual(self.req('GET',f'/organizations/edit/{oid}')[0],200)
        self.assertEqual(self.req('POST',f'/organizations/edit/{oid}',{'name':'Brand Beta','country':'NL','sector':'Finance','aliases':'Beta'})[0],303)
        self.assertEqual(self.req('POST',f'/organizations/archive/{oid}')[0],303)
        self.assertNotIn('Brand Beta',self.req('GET','/')[1])
        self.assertEqual(self.req('POST',f'/organizations/restore/{oid}')[0],303)
        self.assertIn('Brand Beta',self.req('GET','/')[1])

    def test_web_source_scope_and_toggle(self):
        self.assertIn('Франция',self.req('GET','/sources')[1])
        self.assertEqual(self.req('POST','/sources/toggle',{'source_id':'zataz-direct','enabled':'1'})[0],303)
        c=connect(self.db)
        try:self.assertTrue(next(s for s in all_sources(c) if s['id']=='zataz-direct')['enabled'])
        finally:c.close()
        self.assertEqual(self.req('POST','/sources/bulk',{'scope':'FR','enabled':'0'})[0],303)
        c=connect(self.db)
        try:self.assertFalse(next(s for s in all_sources(c) if s['id']=='zataz-direct')['enabled'])
        finally:c.close()

    def test_documented_relation_approval(self):
        s,body,_=self.req('GET','/graph?org_id=one')
        self.assertEqual(s,200);self.assertIn('Добавить подтверждаемую связь',body)
        self.assertIn('Пока нет связей',body)
        self.assertEqual(self.req('POST','/relations/add',{'source_org_id':'one','target_org_id':'two',
                   'relation_type':'supplier','evidence_url':'https://example.org/press-release'})[0],303)
        c=connect(self.db)
        try:
            rid=c.execute('SELECT id FROM organization_relations').fetchone()['id']
            self.assertEqual(c.execute('SELECT review_status FROM organization_relations').fetchone()[0],'unverified')
        finally:c.close()
        self.assertIn('Подтвердить',self.req('GET','/graph?org_id=one')[1])
        self.assertEqual(self.req('POST',f'/relations/verify/{rid}')[0],303)
        self.assertIn('Схема связей',self.req('GET','/graph?org_id=one')[1])

    def test_refuse_unverified_url_and_fake_source(self):
        self.assertEqual(self.req('POST','/relations/add',{'source_org_id':'one','target_org_id':'two',
                  'relation_type':'supplier','evidence_url':'http://example.com'})[0],400)
        self.assertEqual(self.req('POST','/sources/toggle',{'source_id':'bogus','enabled':'1'})[0],400)

if __name__=='__main__':unittest.main()
