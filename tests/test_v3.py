"""Offline regression tests for v3. Synthetic samples are not real evidence."""
import csv
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threatwatch.config import load_sources,load_organizations
from threatwatch.store import connect,upsert_organizations,add_item,add_discovery
from threatwatch.briefs import local_brief
from threatwatch.social_sources import parse_mastodon,parse_telegram_public
from threatwatch.fulltext import parse_article_html, enrich_pages
from threatwatch.dashboard import org_page,discovery_page,sources_page
from threatwatch.normalize import utc_now
from threatwatch.feeds import Article
from threatwatch.pipeline import run_once
from threatwatch.text_model import read_examples,train,predict


class SocialTests(unittest.TestCase):
    def test_mastodon_public_only(self):
        posts=[{'url':'https://mastodon.social/@a/123','created_at':utc_now(),
                'visibility':'public','content':'<p>EDF cyberattaque — déclaration non vérifiée</p>',
                'account':{'acct':'a'}},
               {'url':'https://mastodon.social/@a/124','created_at':utc_now(),
                'visibility':'private','content':'ignore'}]
        result=parse_mastodon(posts,'Mastodon',limit=30)
        self.assertEqual(len(result),1)
        self.assertIn('EDF',result[0].summary)
        self.assertNotIn('<p>',result[0].summary)
    def test_telegram_public_preview(self):
        html=b'''<div class="tgme_widget_message_wrap"><div class="tgme_widget_message" data-post="testChannel/12"><div class="tgme_widget_message_text">DDOS mentions <b>EDF</b></div><time datetime="2026-10-20T15:00:00+00:00"></time></div></div>'''
        articles=parse_telegram_public(html,'Telegram test','testChannel')
        self.assertEqual(len(articles),1)
        self.assertEqual(articles[0].url,'https://t.me/testChannel/12')
    def test_mastodon_bad_payload(self):
        with self.assertRaises(ValueError):parse_mastodon({'error':'denied'},'Mastodon')
    def test_source_configuration(self):
        types={s['type'] for s in load_sources(include_disabled=True)}
        self.assertIn('mastodon_tag',types)
        # v4 replaces per-organization queries with global incident discovery.
        self.assertIn('gdelt_doc',types)
        self.assertGreaterEqual(len(load_organizations()),16)


class MoreCollection(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.con=connect(Path(self.tmp.name)/'db.sqlite')
        upsert_organizations(self.con,load_organizations())
    def tearDown(self):
        self.con.close();self.tmp.cleanup()
    def test_unmatched_cyber_article_in_discovery(self):
        def mocked(sources,orgs,delay=0):
            yield 'Example News',[Article('AnotherCo cyberattaque','Reported allegation','https://news.test/123',utc_now(),'Example','news.test')],None
        with patch('threatwatch.pipeline.collect_feeds',mocked):
            report=run_once(self.con,organizations=load_organizations(),sources=[],delay=0)
        self.assertEqual(report['catalogued_unmatched'],1)
        self.assertEqual(self.con.execute('SELECT count(*) FROM items').fetchone()[0],0)
        self.assertIn('AnotherCo',discovery_page(self.con).decode())
    def test_context_not_threat_score(self):
        def mocked(sources,orgs,delay=0):
            yield 'Google News — organization context / Ville de Paris',[Article(
              'Ville de Paris: manifestations en octobre','Les événements sociaux',
              'https://news.test/context',utc_now(),'Example','news.test')],None
        with patch('threatwatch.pipeline.collect_feeds',mocked):
            report=run_once(self.con,organizations=load_organizations(),sources=[],delay=0)
        self.assertEqual(report['context_items'],1)
        self.assertEqual(self.con.execute("SELECT kind FROM items").fetchone()['kind'],'context')
        self.assertEqual(local_brief(self.con,'ville-de-paris')['counts']['cyber'],0)
    def test_brief_links_provenance_and_html_escaping(self):
        add_item(self.con,url='https://news.test/a',title='<script>EDF attack</script>',
            summary='claim only',source_name='Reporter',source_group='news.test',
            published_at=utc_now(),kind='claim',confidence=.7,rationale='',org_ids=['edf'])
        b=local_brief(self.con,'edf')
        self.assertEqual(len(b['evidence']),1)
        page=org_page(self.con,'edf').decode()
        self.assertIn('Почему организация рассматривается',page)
        self.assertIn('https://news.test/a',page)
        self.assertNotIn('<script>EDF attack</script>',page)
        self.assertIn('&lt;script&gt;',page)
    def test_source_health_page(self):
        self.con.execute("INSERT INTO source_checks(checked_at,source_name,source_group,status,fetched,error) VALUES (?,?,?,?,?,?)",
                         (utc_now(),'Test Feed','test','ok',10,''))
        self.con.commit()
        self.assertIn('Test Feed',sources_page(self.con).decode())


class EditorialTests(unittest.TestCase):
    def test_extraction(self):
        html=b'<html><nav>Navigation</nav><article><h1>Story</h1><p>Some factual body text</p></article><script>evil()</script></html>'
        text=parse_article_html(html)
        self.assertIn('Some factual body text',text)
        self.assertNotIn('evil()',text)
    def test_refuse_arbitrary_host_without_request(self):
        with tempfile.TemporaryDirectory() as td:
            con=connect(Path(td)/'db.sqlite');upsert_organizations(con,load_organizations())
            add_item(con,url='https://example.com/edf',title='EDF cyberattack',summary='',
                source_name='Test',published_at=utc_now(),kind='claim',confidence=.5,
                rationale='',org_ids=['edf'])
            with patch('threatwatch.fulltext.fetch_bytes',side_effect=AssertionError('Should not fetch')):
                res=enrich_pages(con,limit=5,delay=0)
            self.assertEqual(res['checked'],0)
            self.assertEqual(res['skipped_unapproved_hosts'],1)
            con.close()


class TextMLTests(unittest.TestCase):
    def test_refuse_unlabelled_training(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'labels.csv'
            path.write_text('published_at,title,summary,label,story_group\n2026-10-01,Example text,Some cyber text,,abc\n',encoding='utf-8')
            with self.assertRaises(ValueError):read_examples(path)
    def test_small_sample_gated(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'labels.csv';out=Path(td)/'model.joblib'
            with path.open('w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=['published_at','title','summary','label','story_group'])
                w.writeheader()
                for i in range(10):
                    w.writerow({'published_at':f'2026-10-{i+1:02d}','title':'Reported ransomware event sample',
                         'summary':f'Synthetic story {i} not genuine','label':'claim','story_group':f's{i}'})
            result=train(path,out)
            self.assertEqual(result['status'],'not_trained')
            self.assertFalse(out.exists())
    def test_chronological_holdout_training(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'labels.csv';out=Path(td)/'model.joblib'
            start=dt.date(2026,6,1)
            with path.open('w',newline='',encoding='utf-8') as f:
                w=csv.DictWriter(f,fieldnames=['published_at','title','summary','label','story_group'])
                w.writeheader()
                for i in range(100):
                    label=['claim','context'][i%2]
                    title=(f'Unverified ransomware group announcement incident {i}' if label=='claim'
                        else f'Municipal funding cultural activity meeting {i}')
                    w.writerow({'published_at':str(start+dt.timedelta(days=i)),
                          'title':title,'summary':'Synthetic training example prepared only for test',
                          'label':label,'story_group':f'unique-story-{i}'})
            result=train(path,out)
            self.assertEqual(result['status'],'trained_text_classifier_not_breach_forecast')
            self.assertTrue(out.exists())
            self.assertGreater(result['accuracy'],result['baseline_accuracy'])
            self.assertGreater(predict(out,'Ransomware group announcement about a new claim')['confidence'],.5)


if __name__=='__main__':unittest.main()

class MigrationTests(unittest.TestCase):
    def test_read_only_commands_do_not_append_history(self):
        from threatwatch.cli import initialize
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'db.sqlite';con=connect(path)
            initialize(con)
            count=con.execute('SELECT count(*) FROM scores').fetchone()[0]
            initialize(con)
            after=con.execute('SELECT count(*) FROM scores').fetchone()[0]
            self.assertEqual(count,after)
            con.close()
    def test_new_tables_additive(self):
        with tempfile.TemporaryDirectory() as td:
            path=Path(td)/'db.sqlite'
            # Existing v2 databases did not have these tables.
            import sqlite3
            with sqlite3.connect(path) as old:
                old.execute('CREATE TABLE existing_legacy_info(key TEXT PRIMARY KEY)')
                old.execute("INSERT INTO existing_legacy_info VALUES ('preserved')")
            con=connect(path)
            self.assertEqual(con.execute('SELECT key FROM existing_legacy_info').fetchone()[0],'preserved')
            self.assertIsNotNone(con.execute("SELECT name FROM sqlite_master WHERE name='discovery'").fetchone())
            self.assertIsNotNone(con.execute("SELECT name FROM sqlite_master WHERE name='org_briefs'").fetchone())
            con.close()
