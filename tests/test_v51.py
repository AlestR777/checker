"""Tests for one-click browser app, web actions, audit, API backoff."""
from __future__ import annotations
import datetime as dt
import http.client
import json
import re
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from http.server import ThreadingHTTPServer
from urllib.parse import urlencode
from threatwatch.store import connect
from threatwatch.control import CollectionController
from threatwatch.audit_web import generate,save,progress,pending,evaluate
from threatwatch.dashboard import make_handler
from threatwatch.feeds import collect_feeds
from threatwatch.config import load_organizations
from threatwatch.pipeline import run_once
from threatwatch.normalize import utc_now

class TestV51(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=Path(self.tmp.name)/'db.sqlite'
        self.con=connect(self.db)
    def tearDown(self):
        self.con.close()
        self.tmp.cleanup()

    def test_audit_queue_with_independent_human_labels(self):
        from threatwatch.store import add_discovery
        for i in range(30):
            add_discovery(self.con,url=f'https://example.org/article/{i}',title=f'Company{i} ransomware claim',
                summary='Cyberincident',source_name='Example',source_group='example.org',
                published_at='2026-10-25T10:00:00+00:00',kind='claim',candidate_name='')
        self.assertEqual(generate(self.con,size=20)['added'],20)
        self.assertEqual(generate(self.con,size=20)['added'],0)
        row=pending(self.con)
        save(self.con,row['url_key'],'Company0|Company1')
        self.assertEqual(progress(self.con)['reviewed'],1)
        self.assertEqual(evaluate(self.con)['reviewed_articles'],1)
        with self.assertRaises(ValueError):save(self.con,row['url_key'],'')

    def test_controller_prevents_parallel_runs(self):
        def fake_run(*a,**k):time.sleep(.2);return {'inserted':3,'errors':[]}
        ctl=CollectionController(self.db,interval_hours=6)
        with patch('threatwatch.control.run_once',fake_run):
            self.assertTrue(ctl.run_now()[0])
            self.assertFalse(ctl.run_now()[0])
            ctl._run_thread.join(timeout=2)
        self.assertFalse(ctl.status()['busy'])
        self.assertEqual(ctl.status()['result']['inserted'],3)
        self.assertTrue(ctl.schedule()[0]);self.assertFalse(ctl.schedule()[0])
        self.assertTrue(ctl.unschedule()[0])
        self.assertFalse(ctl.status()['scheduled'])

    def test_gdelt_limit_skips_subsequent_request_in_same_batch(self):
        sources=[{'name':'GDELT — one','type':'gdelt_doc','url':'','query':'ransomware','enabled':True},
                 {'name':'GDELT — two','type':'gdelt_doc','url':'','query':'cyberattack','enabled':True}]
        with patch('threatwatch.gdelt.load_articles',side_effect=RuntimeError('HTTP Error 429: Too Many Requests')) as load:
            jobs=list(collect_feeds(sources,[],delay=0))
        self.assertEqual(load.call_count,1)
        self.assertIn('429',jobs[0][2]);self.assertTrue(jobs[1][2].startswith('SKIPPED_COOLDOWN'))

    def test_recent_gdelt_429_cooldown_persists_in_database(self):
        self.con.execute('''INSERT INTO source_checks (checked_at,source_name,source_group,status,fetched,error)
             VALUES(?,?,?,?,?,?)''',(utc_now(),'GDELT — one','gdelt','error',0,'HTTP Error 429: Too Many Requests'))
        self.con.commit()
        called=[]
        def fake(src,orgs,delay=0,skip_names=None):
            called.append(skip_names)
            yield 'GDELT — one',[],'SKIPPED_COOLDOWN: rate limit'
        with patch('threatwatch.pipeline.collect_feeds',fake):
            r=run_once(self.con,sources=[],organizations=[],delay=0)
        self.assertIn('GDELT — one',called[0]);self.assertEqual(r['skipped_rate_limited_sources'],1)
        self.assertEqual(r['checked'],0)

    def test_headline_subject_excludes_reporting_verbs(self):
        from threatwatch.entity_graph import extract_headline_subject
        self.assertEqual(extract_headline_subject('Communauto says it was hit by cyberattack'),'Communauto')

    def test_desktop_cli_opens_browser_mode(self):
        from threatwatch.cli import main
        with patch('threatwatch.cli.serve') as mocked:
            main(['--db',str(self.db),'desktop'])
        self.assertTrue(mocked.call_args.kwargs['open_browser'])

    def test_csv_export_formula_sanitization(self):
        from threatwatch.dashboard import csv_safe
        self.assertEqual(csv_safe('=HYPERLINK("https://bad","x")')[0],"'")
        self.assertEqual(csv_safe('Ordinary news'), 'Ordinary news')

    def test_web_local_actions_csrf_and_exports(self):
        ctl=CollectionController(self.db)
        srv=ThreadingHTTPServer(('127.0.0.1',0),make_handler(self.db,ctl))
        thread=threading.Thread(target=srv.serve_forever,daemon=True);thread.start()
        try:
            port=srv.server_address[1]
            def req(method,path,body='',headers=None):
                conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
                hdr=headers or {}
                if method=='POST':hdr={'Content-Type':'application/x-www-form-urlencoded',**hdr}
                conn.request(method,path,body=body,headers=hdr)
                response=conn.getresponse(); data=response.read().decode('utf-8-sig','replace')
                status=response.status;loc=response.getheader('Location')
                conn.close();return status,data,loc
            status,body,_=req('GET','/control')
            self.assertEqual(status,200)
            self.assertIn('Управление',body)
            csrf=re.search(r'name="csrf" value="([^"]+)"',body).group(1)
            self.assertEqual(req('POST','/control/schedule',urlencode({'csrf':'wrong'}))[0],403)
            self.assertEqual(req('POST','/control/schedule',urlencode({'csrf':csrf}),headers={'Origin':'https://evil.example'})[0],403)
            self.assertEqual(req('POST','/control/schedule',urlencode({'csrf':csrf}))[0],303)
            self.assertTrue(ctl.status()['scheduled'])
            self.assertEqual(req('POST','/control/stop',urlencode({'csrf':csrf}))[0],303)
            self.assertFalse(ctl.status()['scheduled'])
            self.assertEqual(req('GET','/audit')[0],200)
            self.assertEqual(req('POST','/audit/create',urlencode({'csrf':csrf}))[0],303)
            self.assertEqual(req('GET','/export/entities')[0],200)
            self.assertEqual(req('GET','/api/organizations')[0],200)
            self.assertEqual(req('GET','/control',headers={'Host':'evil.example'})[0],403)
        finally:
            ctl.shutdown();srv.shutdown();srv.server_close();thread.join(timeout=2)

if __name__=='__main__':unittest.main()
