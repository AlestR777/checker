"""Risk-policy invariants: reporting volume must not masquerade as exposure."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path

from threatwatch.config import Organization
from threatwatch.normalize import utc_now
from threatwatch.scoring import assess_all, assess_risk
from threatwatch.store import add_item, connect, review_item, upsert_organizations


class RiskAssessmentTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.con = connect(Path(folder.name) / 'risk.sqlite')
        self.addCleanup(self.con.close)
        upsert_organizations(self.con, [
            Organization('a','Alpha','energy','FR',('Alpha',)),
            Organization('b','Beta','energy','DE',('Beta',)),
            Organization('c','Gamma','finance','US',('Gamma',)),
        ])
        self.now = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=5)
        self.serial = 0

    def item(self, org='a', age=0, kind='threat_statement', title='Alpha ransomware threat', **extra):
        self.serial += 1
        args = dict(url=f'https://publisher{self.serial}.test/story', title=title,
            summary='Published claim, not a verified attack', source_name=f'Publisher {self.serial}',
            source_group=f'publisher{self.serial}.test',
            published_at=(self.now-dt.timedelta(days=age)).isoformat(), kind=kind,
            confidence=.6, rationale='Rule classification', org_ids=[org])
        args.update(extra)
        add_item(self.con, **args)
        return self.serial

    def assess(self, org='a', **kwargs):
        return assess_risk(self.con, org, now=self.now, **kwargs)

    def relation(self, source='a', target='c', status='verified', kind='supplier', url='https://official.test/tie'):
        self.con.execute('''INSERT INTO organization_relations
            (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at,verified_at)
            VALUES (?,?,?,?,?,?,?)''', (source,target,kind,url,status,utc_now(),
                                       utc_now() if status=='verified' else None))
        self.con.commit()

    def test_empty_and_broken_collector_are_unknown_not_zero(self):
        result = self.assess()
        self.assertIsNone(result['score'])
        self.assertEqual(result['status'], 'no_signals')
        self.assertEqual(result['confidence']['level'], 'none')
        self.assertEqual(result['data_health']['collection_status'], 'never_run')
        self.con.execute('''INSERT INTO source_checks
            (checked_at,source_name,source_group,status,error) VALUES (?,?,?,'error',?)''',
            (utc_now(),'Feed','feed.test','timeout'))
        result = self.assess()
        self.assertIsNone(result['score'])
        self.assertEqual(result['data_health']['sources_error'], 1)
        self.assertEqual(result['data_health']['collection_status'], 'partial')

    def test_syndication_and_human_review_do_not_increase_risk(self):
        self.item()
        first = self.assess()
        for _ in range(8):
            self.item()
        repeated = self.assess()
        self.assertEqual(first['score'], repeated['score'])
        self.assertEqual(repeated['counts']['events'], 1)
        self.assertEqual(repeated['counts']['articles'], 9)
        self.assertEqual(repeated['confidence']['level'], 'medium')
        review_item(self.con, 1, 'confirmed')
        reviewed = self.assess()
        self.assertEqual(first['score'], reviewed['score'])
        self.assertEqual(reviewed['counts']['reviewed_events'], 1)

    def test_cross_kind_same_story_is_single_event(self):
        self.item(kind='claim')
        self.item(kind='incident_report')
        result = self.assess()
        self.assertEqual(result['counts']['events'], 1)
        self.assertEqual(result['score'], 35)
        self.assertEqual(result['counts']['incidents'], 1)

    def test_identical_repost_does_not_reset_freshness(self):
        self.item(age=8)
        original = self.assess()
        self.item(age=0)
        self.assertEqual(self.assess()['counts']['events'], 1)
        self.assertEqual(self.assess()['score'], original['score'])

    def test_old_outside_window_repost_stays_expired_but_new_event_counts(self):
        self.item(age=45, title='Alpha ransomware threat from original campaign')
        self.item(age=0, title='Alpha ransomware threat from original campaign')
        expired = self.assess()
        self.assertIsNone(expired['score'])
        self.assertEqual(expired['counts']['events'], 0)
        self.assertEqual(expired['evidence'], [])
        self.item(age=0, kind='incident_report', title='Credentials stolen through newly compromised payment supplier')
        fresh = self.assess()
        self.assertEqual(fresh['score'], 35)
        self.assertEqual(fresh['counts']['events'], 1)
        self.assertEqual(fresh['evidence'][0]['title'],
                         'Credentials stolen through newly compromised payment supplier')

    def test_decay_and_future_exclusion(self):
        self.item(age=7)
        result = self.assess()
        self.assertAlmostEqual(result['direct_score'], 27.5, places=1)
        self.item(age=-1, title='Completely new threat tomorrow')
        self.assertEqual(self.assess()['score'], result['score'])
        self.item(age=31, title='Historic attack no longer in lookback')
        self.assertEqual(self.assess()['score'], result['score'])

    def test_disputed_downweighted_rejected_excluded(self):
        row = self.item()
        original = self.assess()['score']
        review_item(self.con,row,'disputed')
        self.assertLess(self.assess()['score'], original)
        review_item(self.con,row,'rejected')
        self.assertIsNone(self.assess()['score'])

    def test_related_is_bounded_and_requires_verified_citation(self):
        self.item(org='c')
        self.relation(status='unverified')
        self.assertIsNone(self.assess()['score'])
        self.relation(url='https://official.test/verified')
        result = self.assess()
        self.assertEqual(result['status'], 'context_only')
        self.assertEqual(result['direct_score'], 0)
        self.assertGreater(result['related_score'], 0)
        self.assertLessEqual(result['related_score'], 15)
        self.relation(kind='partner',url='https://official.test/duplicate-citation')
        self.assertEqual(self.assess()['score'], result['score'])
        self.assertEqual(len(self.assess()['relationships']['affected_peers']), 1)

    def test_sector_is_separate_from_corporate_relations(self):
        self.item(org='b')
        result = self.assess()
        self.assertEqual(result['status'], 'context_only')
        self.assertGreater(result['sector_score'], 0)
        self.assertEqual(result['related_score'], 0)
        self.assertEqual(result['relationships']['verified'], 0)

    def test_synthetic_does_not_contaminate_real_assessment(self):
        self.item(origin='synthetic')
        self.assertIsNone(self.assess()['score'])
        self.assertEqual(self.assess()['ignored']['synthetic'], 1)
        self.assertIsNotNone(self.assess(include_synthetic=True)['score'])
        self.assertTrue(self.assess(include_synthetic=True)['evidence'][0]['synthetic'])

    def test_cyrillic_different_stories_are_not_collapsed(self):
        self.item(title='Организация Альфа получила прямую угрозу')
        self.item(title='Новая утечка в дочерней компании', kind='incident_report')
        self.assertEqual(self.assess()['counts']['events'], 2)

    def test_prior_ingestion_cutoff_and_read_only(self):
        self.item(age=2)
        historic = assess_risk(self.con,'a',now=self.now-dt.timedelta(days=1))
        self.assertIsNone(historic['score'])
        self.assess()
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM scores').fetchone()[0], 0)

    def test_assess_all_excludes_inactive_and_validates_arguments(self):
        from threatwatch.registry import activate
        activate(self.con,'b',False)
        self.assertEqual({r['org_id'] for r in assess_all(self.con)}, {'a','c'})
        with self.assertRaises(ValueError):
            self.assess('missing')
        with self.assertRaises(ValueError):
            self.assess(lookback_days=0)
        with self.assertRaises(ValueError):
            assess_risk(self.con,'a',now=dt.datetime.now())

    def test_total_bounded_and_no_unreviewed_boost(self):
        for idx in range(15):
            self.item(title=f'Distinct attack vector {idx} unique payload {idx*7}',age=idx*.01)
        result = self.assess()
        self.assertLessEqual(result['direct_score'],75)
        self.assertLessEqual(result['score'],100)
        self.assertEqual(result['score_max'],100)

    def test_security_reporter_excluded_but_victim_in_same_article_retained(self):
        upsert_organizations(self.con, [
            Organization('vendor','Microsoft','software','US',('Microsoft',)),
            Organization('victim','Acme','retail','US',('Acme',))])
        self.item(org='vendor',org_ids=['vendor','victim'],kind='incident_report',
                  title='Microsoft researchers warn of ransomware attacks on Acme')
        vendor = self.assess('vendor')
        victim = self.assess('victim')
        self.assertEqual(vendor['direct_score'],0)
        self.assertEqual(vendor['ignored']['reporter_context'],1)
        self.assertEqual(victim['direct_score'],35)
        self.assertEqual(victim['ignored']['reporter_context'],0)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM items').fetchone()[0],1)
        self.assertEqual(self.con.execute('SELECT COUNT(*) FROM mentions').fetchone()[0],2)

    def test_vendor_warns_not_victim_but_confirms_own_breach_is(self):
        upsert_organizations(self.con,[Organization('vendor','Microsoft','software','US',('Microsoft',))])
        self.item(org='vendor',kind='incident_report',
                  title='Microsoft warns of ransomware affecting hospitals')
        self.assertIsNone(self.assess('vendor')['score'])
        self.item(org='vendor',kind='incident_report', title='Microsoft confirms data breach')
        self.assertEqual(self.assess('vendor')['direct_score'],35)
        self.assertEqual(self.assess('vendor')['counts']['events'],1)

    def test_bare_warns_is_reporter_context(self):
        upsert_organizations(self.con,[Organization('vendor','Microsoft','software','US',('Microsoft',))])
        self.item(org='vendor',kind='threat_statement',
                  title='Microsoft warns ransomware threatens hospitals worldwide')
        result = self.assess('vendor')
        self.assertIsNone(result['score'])
        self.assertEqual(result['ignored']['reporter_context'],1)

    def test_evidence_contributions_respect_direct_cap(self):
        for title in ['Targeted ransomware ultimatum', 'Credentials targeted through supplier',
                      'Extortion group threatens release', 'Political attackers issue manifesto']:
            self.item(title=title)
        result = self.assess()
        self.assertEqual(result['counts']['events'],4)
        self.assertEqual(result['direct_score'],75)
        attributed = sum(e['contribution'] for e in result['evidence'])
        self.assertLessEqual(attributed,75)
        self.assertAlmostEqual(attributed,result['direct_score'],places=1)

    def test_russian_reporter_alias_and_explicit_target_override(self):
        from threatwatch.registry import change_details
        change_details(self.con,'a',name='Альфа',country='RU',sector='software',
                       aliases='Лаборатории Альфа | Alpha Labs')
        self.item(title='По данным Лаборатории Альфа, вредоносная программа атакует банки',
                  kind='incident_report')
        self.item(title='Alpha Labs researchers warn of credential theft',kind='incident_report')
        result = self.assess()
        self.assertIsNone(result['score'])
        self.assertEqual(result['ignored']['reporter_context'],2)
        self.item(title='Исследователи Альфа сообщают: атака на Альфа продолжается',
                  kind='incident_report')
        result = self.assess()
        self.assertEqual(result['direct_score'],35)
        self.assertEqual(result['counts']['events'],1)


if __name__ == '__main__':
    unittest.main()
