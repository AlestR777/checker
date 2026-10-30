import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from threatwatch.config import load_organizations, Organization
from threatwatch.feeds import parse_feed, google_rss,source_definitions
from threatwatch.normalize import (normalize_url, matching_organizations,parse_date,
                                   classify_rule,title_similarity)
from threatwatch.store import connect,upsert_organizations,add_item,recent_items,event_groups,review_item
from threatwatch.scoring import compute_score,compare_windows
from threatwatch.demo import populate
from threatwatch.dashboard import home,org_page


class TextTests(unittest.TestCase):
    def test_dates(self):
        self.assertEqual(parse_date("Thu, 29 Oct 2026 10:00:00 GMT")[:10], "2026-10-29")
        self.assertIsNone(parse_date("unknown"))
    def test_url_normalized(self):
        self.assertEqual(normalize_url("https://x.test/post/?utm_source=x&b=2"),"https://x.test/post?b=2")
        self.assertEqual(normalize_url("javascript:alert(1)"),"")
    def test_matching(self):
        orgs=load_organizations()
        self.assertIn("les-republicains",matching_organizations("Cyberattaque Les Républicains",orgs))
        self.assertIn("edf",matching_organizations("Cyberattaque EDF",orgs))
        self.assertNotIn("edf",matching_organizations("EDF annonce ses résultats trimestriels",orgs))
        self.assertNotIn("ville-de-paris",matching_organizations("Protest in Paris",orgs))
    def test_classify(self):
        self.assertEqual(classify_rule("DDoS revendiqué contre EDF","Un groupe revendique une attaque")[0],"claim")
        self.assertEqual(classify_rule("Vulnérabilité dans un logiciel","CVE-2026-9999")[0],"advisory")
    def test_similarity(self):
        self.assertGreater(title_similarity("Cyberattaque contre EDF","EDF cyberattaque contre"),.95)
    def test_feed_rss(self):
        feed=b'''<rss><channel><item><title>Incident EDF</title><link>https://example.com/post</link><pubDate>Thu, 29 Oct 2026 10:00:00 GMT</pubDate><description>Some &lt;b&gt;thing&lt;/b&gt;</description><source url="https://newspaper.fr">Newspaper</source></item></channel></rss>'''
        r=parse_feed(feed,"Example")
        self.assertEqual(len(r),1)
        self.assertEqual(r[0].source_group,"newspaper.fr")
        self.assertIn("thing",r[0].summary)
    def test_feed_atom(self):
        x=b'''<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>A</title><link href="https://example.org/a"/><updated>2026-10-01T12:00:00Z</updated></entry></feed>'''
        self.assertEqual(parse_feed(x,"Atom")[0].published_at[:10],"2026-10-01")


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.con=connect(Path(self.tmp.name)/"db.sqlite")
        self.orgs=load_organizations()
        upsert_organizations(self.con,self.orgs)
    def tearDown(self):
        self.con.close();self.tmp.cleanup()
    def test_insert_dedup(self):
        kws=dict(url="https://site.fr/story?utm_source=abc",title="Cyberattaque EDF",summary="report",source_name="A",source_group="a.fr",
                 published_at="2026-10-17T00:00:00+00:00",kind="claim",confidence=.6,rationale="Allegation",org_ids=["edf"])
        self.assertTrue(add_item(self.con,**kws))
        kws["url"]="https://site.fr/story"
        self.assertFalse(add_item(self.con,**kws))
        self.assertEqual(len(recent_items(self.con,"edf")),1)
        self.assertTrue(review_item(self.con,1,"disputed"))
    def test_cross_source_clustering(self):
        date="2026-10-17T00:00:00+00:00"
        for n in [1,2]:
            add_item(self.con,url=f"https://source{n}.fr/post",title="Cyberattaque contre EDF",
                     summary="Allegation",source_name=f"Source {n}",source_group=f"source{n}.fr",
                     published_at=date,kind="claim",confidence=.5,rationale="Claim",org_ids=["edf"])
        clusters=event_groups(self.con,"edf","2026-10-01")
        self.assertEqual(len(clusters),1)
        self.assertEqual(clusters[0]["independent_sources"],2)
    def test_demo_and_dashboard(self):
        self.assertGreater(populate(self.con),0)
        r=compute_score(self.con,"les-republicains")
        self.assertIsNotNone(r["score"])
        self.assertIn(b"ThreatWatch",home(self.con))
        self.assertIn(b"Les",org_page(self.con,"les-republicains"))
        self.assertIsNone(org_page(self.con,"unknown"))
    def test_no_data_unknown(self):
        r=compute_score(self.con,"carrefour")
        self.assertIsNone(r["score"])
        self.assertEqual(r["status"],"insufficient_evidence")
    def test_compare(self):
        add_item(self.con,url="https://source.fr/a",title="Cyberattaque EDF",
                 summary="Allegation",source_name="a",source_group="source.fr",
                 published_at="2026-10-15T12:00:00+00:00",kind="claim",confidence=.6,
                 rationale="claim",org_ids=["edf"])
        r=compare_windows(self.con,"edf")
        self.assertEqual(r["before_count"],1)
        self.assertEqual(r["after_count"],0)


if __name__=="__main__":
    unittest.main()

class PipelineTests(unittest.TestCase):
    def test_entire_pipeline_from_mock_public_feed(self):
        from threatwatch.pipeline import run_once
        from threatwatch.feeds import Article
        from threatwatch.normalize import utc_now
        orgs=load_organizations()
        with tempfile.TemporaryDirectory() as folder:
            con=connect(Path(folder)/"research.sqlite")
            def fake_feeds(sources,orgs,delay=0):
                yield "Mock public RSS",[
                  Article("DDoS revendiqué contre EDF", "Un groupe revendique une cyberattaque", "https://press-a.test/post1",utc_now(),"Press A","press-a.test"),
                  Article("DDoS revendiqué contre EDF", "La presse rapporte un incident", "https://press-b.test/post2",utc_now(),"Press B","press-b.test"),
                  Article("Only political discussion", "A non-cyber story", "https://press-b.test/post3",utc_now(),"Press B","press-b.test"),
                ],None
            with patch("threatwatch.pipeline.collect_feeds",fake_feeds):
                result=run_once(con,organizations=orgs,sources=[],delay=0)
            self.assertEqual(result["inserted"],2)
            self.assertEqual(result["checked"],1)
            self.assertEqual(len(event_groups(con,"edf","2026-01-01")),1)
            self.assertEqual(len(recent_items(con,"edf")),2)
            self.assertIsNotNone(compute_score(con,"edf")["score"])
            con.close()

    def test_multi_organization_one_public_article(self):
        with tempfile.TemporaryDirectory() as folder:
            con=connect(Path(folder)/"db.sqlite")
            upsert_organizations(con,load_organizations())
            row=dict(url="https://report.test/both",title="Cyberattaque EDF et Carrefour",summary="Reported claim",
                     source_name="Press",source_group="press.test",published_at="2026-10-20T10:00:00+00:00",
                     kind="claim",confidence=.5,rationale="Unverified")
            self.assertTrue(add_item(con,**row,org_ids=["edf"]))
            self.assertFalse(add_item(con,**row,org_ids=["carrefour"]))
            self.assertEqual(len(recent_items(con,"carrefour")),1)
            self.assertEqual(con.execute("SELECT COUNT(*) FROM items").fetchone()[0],1)
            con.close()
