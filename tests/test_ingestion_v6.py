"""Regression checks for watchlist changes and retained evidence."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threatwatch.config import Organization
from threatwatch.feeds import Article
from threatwatch.normalize import utc_now
from threatwatch.pipeline import reconcile_mentions, reconcile_discovery, run_once
from threatwatch.store import connect, upsert_organizations, add_item, add_discovery


class LinkRepairTests(unittest.TestCase):
    def setUp(self):
        tmp=tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.con=connect(Path(tmp.name)/'ledger.sqlite'); self.addCleanup(self.con.close)
        self.orgs=[Organization('alpha','Alpha Systems','technology','US',('Alpha Systems',)),
                   Organization('beta','Beta Logistics','transport','JP',('Beta Logistics',))]
        upsert_organizations(self.con,self.orgs)
        self.row=dict(url='https://press.example/story',title='Alpha Systems and Beta Logistics data breach',
                      summary='Companies confirm an incident',source_name='Press',source_group='press.example',
                      published_at=utc_now(),kind='incident_report',confidence=.7,rationale='Original report')
        add_item(self.con,**self.row,org_ids=['alpha'],review_status='disputed')

    def test_repair_retained_items_additive_and_repeatable(self):
        result=reconcile_mentions(self.con,organizations=self.orgs)
        self.assertEqual(result['new_mentions'],1)
        self.assertEqual(reconcile_mentions(self.con,organizations=self.orgs)['new_mentions'],0)
        self.assertEqual(self.con.execute('SELECT count(*) FROM items').fetchone()[0],1)
        self.assertEqual(self.con.execute('SELECT review_status FROM items').fetchone()[0],'disputed')
        self.assertEqual(self.con.execute('SELECT count(*) FROM mentions').fetchone()[0],2)

    def test_duplicate_discovery_keeps_new_link_before_removing_catalogue(self):
        add_discovery(self.con,**{k:self.row[k] for k in
                      ('url','title','summary','source_name','source_group','published_at','kind')})
        result=reconcile_discovery(self.con,organizations=self.orgs)
        self.assertEqual(result['already_present'],1)
        self.assertEqual(self.con.execute('SELECT count(*) FROM discovery').fetchone()[0],0)
        self.assertEqual(self.con.execute('SELECT count(*) FROM mentions').fetchone()[0],2)

    def test_repeat_collection_links_new_org_and_skips_bad_date(self):
        article=Article(self.row['title'],self.row['summary'],self.row['url'],self.row['published_at'],
                        'Press','press.example')
        bad=Article('Alpha Systems data breach','','https://press.example/bad','not-a-date','Press','press.example')
        with patch('threatwatch.pipeline.collect_feeds',return_value=iter([('Press',[article,bad],None)])):
            result=run_once(self.con,organizations=self.orgs,sources=[],delay=0)
        self.assertEqual(result['inserted'],0)
        self.assertEqual(result['relinked_mentions'],1)
        self.assertEqual(result['skipped_undated'],1)
        self.assertEqual(self.con.execute('SELECT count(*) FROM mentions').fetchone()[0],2)

    def test_all_source_errors_are_reported_as_unavailable(self):
        from threatwatch.control import CollectionController
        with patch('threatwatch.pipeline.collect_feeds',return_value=iter([('Press',[],'HTTP Error 403: Forbidden')])):
            result=run_once(self.con,organizations=self.orgs,sources=[],delay=0)
        self.assertEqual(result['source_failures'],result['checked'])
        controller=CollectionController(Path(self.con.execute('PRAGMA database_list').fetchone()[2]))
        with patch('threatwatch.control.run_once',return_value=result):
            controller._worker()
        self.assertIn('Ни один источник',controller.status()['message'])


class TrackerIdentityTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.con=connect(Path(folder.name)/'ledger.sqlite');self.addCleanup(self.con.close)
        self.orgs=[Organization('toyota','Toyota Motor Corporation','manufacturing','JP',('Toyota','Toyota Motor Corporation')),
                   Organization('bank','Банк Пример','finance','RU',('Банк Пример',))]
        upsert_organizations(self.con,self.orgs)

    def test_dealership_is_candidate_not_corporate_victim(self):
        article=Article('Ransomware claim: Lydenburg Toyota','Unverified ransomware listing; country: South Africa',
                        'https://tracker.example/dealer',utc_now(),'Ransomfeed','ransomware-leak-monitors')
        with patch('threatwatch.pipeline.collect_feeds',return_value=iter([('Ransomfeed',[article],None)])):
            result=run_once(self.con,organizations=self.orgs,sources=[],delay=0)
        self.assertEqual(result['inserted'],0)
        self.assertEqual(result['catalogued_unmatched'],1)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mentions WHERE org_id="toyota"').fetchone()[0],0)
        self.assertEqual(self.con.execute('SELECT name FROM entity_candidates').fetchone()[0],'Lydenburg Toyota')
        self.assertEqual(reconcile_discovery(self.con,organizations=self.orgs)['linked'],0)

    def test_exact_aliases_and_unicode_match_but_summary_cannot_expand_target(self):
        from threatwatch.pipeline import matching_article_organizations
        self.assertEqual(matching_article_organizations('Ransomware claim: TOYOTA','',self.orgs),['toyota'])
        self.assertEqual(matching_article_organizations('Ransomware claim: Toyota Motor Corporation','',self.orgs),['toyota'])
        self.assertEqual(matching_article_organizations('Ransomware claim: БАНК ПРИМЕР','',self.orgs),['bank'])
        self.assertEqual(matching_article_organizations('Ransomware claim: Lydenburg Toyota','Toyota Motor Corporation',self.orgs),[])
        self.assertEqual(matching_article_organizations('Toyota confirms data breach','',self.orgs),['toyota'])

    def test_reconcile_retained_tracker_item_does_not_add_false_parent_mention(self):
        dealer=Organization('dealer','Lydenburg Toyota','retail','ZA',('Lydenburg Toyota',))
        upsert_organizations(self.con,[dealer])
        add_item(self.con,url='https://tracker.example/dealer',title='Ransomware claim: Lydenburg Toyota',
                 summary='Ransomware listing',source_name='Ransomfeed',source_group='ransomware-leak-monitors',
                 published_at=utc_now(),kind='claim',confidence=.65,rationale='Unverified claim',org_ids=['dealer'])
        result=reconcile_mentions(self.con,organizations=[*self.orgs,dealer])
        self.assertEqual(result['new_mentions'],0)
        self.assertEqual(self.con.execute('SELECT org_id FROM mentions').fetchone()[0],'dealer')

    def test_ambiguous_tracker_alias_is_not_linked_to_multiple_entities(self):
        from threatwatch.pipeline import matching_article_organizations
        duplicate=Organization('dealer','Toyota Dealer','retail','ZA',('Toyota',))
        self.assertEqual(matching_article_organizations('Ransomware claim: Toyota','',[*self.orgs,duplicate]),[])


if __name__=='__main__': unittest.main()
