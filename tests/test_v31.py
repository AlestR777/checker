"""v3.1 regression tests run entirely offline with synthetic publications."""
import datetime as dt
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from xml.etree.ElementTree import ParseError
from threatwatch.config import load_sources,load_organizations,Organization
from threatwatch.feeds import parse_feed,source_definitions
from threatwatch.local_ai import call_ollama,local_ai_brief,triage_discovery,LocalAIError
from threatwatch.pipeline import reconcile_discovery,run_once
from threatwatch.store import connect,upsert_organizations,add_discovery
from threatwatch.sectors import sector_snapshot
from threatwatch.normalize import utc_now


class ContextManager:
    def __init__(self,obj):self.value=io.BytesIO(json.dumps(obj).encode())
    def __enter__(self):return self.value
    def __exit__(self,*args):return False


class NewSourceTests(unittest.TestCase):
    def test_fixes_bad_cert_endpoint(self):
        items=load_sources(include_disabled=True)
        urls={x['id']:x.get('url','') for x in items}
        self.assertEqual(urls['cert-fr-bulletin'],'https://cert.cyber.gouv.fr/cti/feed/')
        self.assertEqual(urls['cert-fr-news-bulletins'],'https://cert.cyber.gouv.fr/actualite/feed/')
        self.assertIn('zataz-direct',urls)
        self.assertIn('01net-security-direct',urls)
    def test_reject_html_error_with_clear_message(self):
        with self.assertRaisesRegex(ValueError,'returned an HTML page'):
            parse_feed(b'<!DOCTYPE html><html><body>Oops</body></html>','CERT-FR')
        with self.assertRaisesRegex(ValueError,'Invalid RSS/XML response'):
            parse_feed(b'not RSS','CERT-FR')
    def test_google_org_search_alias_expansion(self):
        from urllib.parse import urlsplit,parse_qs
        org=load_organizations()[0]
        defs=source_definitions([{'id':'test','name':'test','type':'google_org_search',
            'query_suffix':'cyberattaque','max_items':10}], [org])
        self.assertEqual(len(defs),1)
        query=parse_qs(urlsplit(defs[0][1]).query)['q'][0]
        self.assertIn('Les Républicains',query)
        self.assertIn('OR',query)


class LocalAITests(unittest.TestCase):
    def test_free_local_model_response(self):
        result={'message':{'content':'{"summary":"Публикаций не обнаружено.","limitations":"Источники неполные."}'}}
        with patch('threatwatch.local_ai.urlopen',return_value=ContextManager(result)) as mocked:
            output=call_ollama('Факты',schema={'type':'object'},model='gemma3:4b')
        self.assertEqual(output['summary'],'Публикаций не обнаружено.')
        request=mocked.call_args.args[0]
        self.assertEqual(request.full_url,'http://127.0.0.1:11434/api/chat')
        payload=json.loads(request.data)
        self.assertEqual(payload['format'],{'type':'object'})
        self.assertFalse(payload['stream'])
    def test_reject_cloud_models(self):
        with self.assertRaisesRegex(LocalAIError,'locally installed'):
            call_ollama('x',schema={},model='gemma4:cloud')


class LocalPipelineTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.db=connect(Path(self.tmp.name)/'test.sqlite')
        self.orgs=load_organizations()
        upsert_organizations(self.db,self.orgs)
    def tearDown(self):
        self.db.close();self.tmp.cleanup()
    def test_sector_context_not_attack_score(self):
        now=dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        earlier=(now-dt.timedelta(days=40)).isoformat()
        news=now.isoformat()
        for i,(day,title) in enumerate([(earlier,'Mairie cyberattaque signalée'),(news,'Des mairies discutent cyberattaque')]):
            add_discovery(self.db,url=f'https://news.example.test/{i}',title=title,
                          summary='France',source_name='News',source_group='news.test',
                          published_at=day,kind='context')
        sector=sector_snapshot(self.db,'public_administration',now=now)
        self.assertEqual(sector['current_articles'],1)
        self.assertEqual(sector['prior_articles'],1)
        from threatwatch.briefs import local_brief
        brief=local_brief(self.db,'ville-de-paris')
        self.assertEqual(brief['counts']['cyber'],0)
        self.assertEqual(brief['status'],'insufficient_evidence')
        self.assertIn('Это общий контекст СМИ',brief['text'])
    def test_reconcile_catalog_after_new_alias(self):
        add_discovery(self.db,url='https://news.example.test/one',title='Organisation nouvelle cyberattaque',
                      summary='Company described in France',source_name='News',source_group='news.test',
                      published_at=utc_now(),kind='claim')
        from threatwatch.config import Organization
        new=Organization('new-org','New Org','manufacturing','FR',('Organisation nouvelle',))
        orgs=self.orgs+[new]
        result=reconcile_discovery(self.db,organizations=orgs)
        self.assertEqual(result['linked'],1)
        self.assertEqual(self.db.execute('SELECT count(*) FROM discovery').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM mentions WHERE org_id=?',('new-org',)).fetchone()[0],1)
        self.assertEqual(reconcile_discovery(self.db,organizations=orgs)['linked'],0)
    def test_triage_is_unverified_and_does_not_edit_scores(self):
        add_discovery(self.db,url='https://news.example.test/one',title='A company suffers hack',
                      summary='Unverified',source_name='News',source_group='news.test',
                      published_at=utc_now(),kind='claim')
        suggestion={'organization_mentions':['AnotherCo'],'relevant_to_france':False,'event_type':'claim','reason':'Claim text'}
        with patch('threatwatch.local_ai.call_ollama',return_value=suggestion):
            out=triage_discovery(self.db,limit=5)
        self.assertEqual(out[0]['status'],'unverified_ai_suggestion')
        self.assertEqual(self.db.execute('SELECT count(*) FROM mentions').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT count(*) FROM discovery').fetchone()[0],1)
    def test_brief_without_llm_still_works(self):
        from threatwatch.briefs import local_brief
        result=local_brief(self.db,'edf')
        self.assertEqual(result['counts']['cyber'],0)


if __name__=='__main__':unittest.main()

class LocalAIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.con=connect(Path(self.tmp.name)/'test.db')
        upsert_organizations(self.con,load_organizations())
    def tearDown(self):
        self.con.close();self.tmp.cleanup()
    def test_ai_brief_saved_and_dashboard_displays_safe_text(self):
        from threatwatch.dashboard import org_page
        with patch('threatwatch.local_ai.call_ollama',return_value={
            'summary':'Известных киберсигналов недостаточно.','limitations':'Источники неполны.'}):
            result=local_ai_brief(self.con,'edf')
        self.assertEqual(result['status'],'local_model_unverified_editorial_summary')
        saved=self.con.execute('SELECT model,text FROM org_briefs WHERE org_id=?',('edf',)).fetchone()
        self.assertTrue(saved['model'].startswith('ollama-local/'))
        page=org_page(self.con,'edf').decode('utf-8')
        self.assertIn('Известных киберсигналов недостаточно.',page)
    def test_suggestions_cached_and_not_scored(self):
        add_discovery(self.con,url='https://example.test/p1',title='UnknownCo hacked',
                      summary='Unverified',source_name='News',source_group='news.test',
                      published_at=utc_now(),kind='claim')
        suggestion={'organization_mentions':['UnknownCo'],
           'relevant_to_france':True,'event_type':'claim','reason':'In headline'}
        with patch('threatwatch.local_ai.call_ollama',return_value=suggestion) as model:
            res1=triage_discovery(self.con,limit=5)
            res2=triage_discovery(self.con,limit=5)
        self.assertEqual(len(res1),1)
        self.assertEqual(len(res2),0)
        self.assertEqual(model.call_count,1)
        self.assertEqual(self.con.execute('SELECT count(*) FROM discovery_suggestions').fetchone()[0],1)
        from threatwatch.dashboard import discovery_page
        self.assertIn('UnknownCo',discovery_page(self.con).decode())
    def test_run_without_ollama_unaffected(self):
        from threatwatch.pipeline import run_once
        with patch('threatwatch.pipeline.collect_feeds',return_value=iter([])):
            out=run_once(self.con,sources=[],organizations=load_organizations(),delay=0,local_ai=False)
        self.assertEqual(out['checked'],0)
        self.assertNotIn('local_ai_status',out)
