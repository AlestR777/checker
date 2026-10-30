"""Offline tests for external adapters, TLS config, Bayesian model and coverage gates."""
import datetime as dt
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threatwatch.claim_sources import parse_ransomlook, parse_ransomware_live
from threatwatch.ransomfeed import parse_claims
from threatwatch.statistics import posterior_predictive, forecast_from_database
from threatwatch.store import connect, upsert_organizations, add_item
from threatwatch.config import load_sources, load_organizations
from threatwatch.feeds import collect_feeds
from threatwatch.pipeline import run_once
from threatwatch.network import fetch_bytes, ssl_context
from threatwatch.normalize import UTC


class Adapters(unittest.TestCase):
    def test_ransomlook_claims_only(self):
        payload=[{'post_title':'EDF','group_name':'Example','discovered':'2026-10-29 10:11:12.123456',
                  'link':'/blog/example/'}]
        posts=parse_ransomlook(payload)
        self.assertEqual(len(posts),1)
        self.assertEqual(posts[0].title,'Ransomware claim: EDF')
        self.assertEqual(posts[0].source_group,'ransomware-leak-monitors')
        self.assertTrue(posts[0].url.startswith('https://www.ransomlook.io/blog/'))
        self.assertIsNotNone(posts[0].published_at)
    def test_ransomware_live_claims_only(self):
        result=parse_ransomware_live({'victims':[{'victim':'EDF','group_name':'A','discovered':'2026-10-20'}]})
        self.assertEqual(len(result),1)
        self.assertIn('api.ransomware.live/v2/recentvictims',result[0].url)
    def test_ransomfeed_api_metadata(self):
        posts=parse_claims({'data':[{'victim':'EDF','gang':'Test','date':'2026-10-21','id':123}]},'Ransomfeed')
        self.assertEqual(len(posts),1)
        self.assertEqual(posts[0].source_group,'ransomware-leak-monitors')
        self.assertIn('/search/EDF',posts[0].url)
        self.assertNotIn('.onion',posts[0].url)
    def test_malformed_api_rejected(self):
        with self.assertRaises(ValueError):
            parse_ransomlook({'unexpected':123})
    def test_source_types_valid(self):
        types={s['type'] for s in load_sources()}
        self.assertIn('ransomfeed_api',types)
        self.assertIn('ransomlook_api',types)
    def test_http_rejected_without_contact(self):
        with self.assertRaises(ValueError):
            fetch_bytes('http://example.com/feed')
    def test_cafile_can_be_provided(self):
        with patch.dict(os.environ,{'THREATWATCH_CA_BUNDLE':'/not/there'},clear=False):
            with self.assertRaises(OSError):
                ssl_context()


class MathTests(unittest.TestCase):
    def test_rate_increases_with_events(self):
        first=posterior_predictive(0,30)
        second=posterior_predictive(3,30)
        self.assertLess(first['probability_of_observed_claim'],second['probability_of_observed_claim'])
        self.assertGreaterEqual(first['probability_of_observed_claim'],0)
        self.assertLessEqual(second['probability_of_observed_claim'],1)
    def test_rate_falls_with_more_zero_days(self):
        self.assertLess(posterior_predictive(2,40)['probability_of_observed_claim'],
                        posterior_predictive(2,14)['probability_of_observed_claim'])
    def test_interval_is_ordered(self):
        p=posterior_predictive(3,25)
        self.assertLess(p['claim_rate_90pct_interval_per_30d'][0],p['claim_rate_90pct_interval_per_30d'][1])
    def test_invalid_params(self):
        with self.assertRaises(ValueError):
            posterior_predictive(-1,20)
    def test_model_gated_by_source_health(self):
        with tempfile.TemporaryDirectory() as tmp:
            con=connect(Path(tmp)/'db.sqlite')
            upsert_organizations(con,load_organizations())
            result=forecast_from_database(con,'edf')
            self.assertEqual(result['status'],'not_estimated')
            con.close()
    def test_model_no_backfill_before_monitoring(self):
        with tempfile.TemporaryDirectory() as tmp:
            con=connect(Path(tmp)/'db.sqlite')
            upsert_organizations(con,load_organizations())
            now=dt.datetime(2026,10,29,12,tzinfo=UTC)
            for i in range(16):
                day=(now-dt.timedelta(days=i)).isoformat()
                for family in ['google-news','ransomlook']:
                    con.execute('INSERT INTO source_checks(checked_at,source_name,source_group,status,fetched,error) VALUES (?,?,?,?,?,?)',
                                (day,family,family,'ok',0,''))
            con.commit()
            add_item(con,url='https://journal.test/old',title='Cyberattaque EDF',summary='',
                     source_name='Journal',source_group='journal.test',published_at='2026-09-30T11:00:00+00:00',
                     kind='claim',confidence=.6,rationale='',org_ids=['edf'])
            val=forecast_from_database(con,'edf',now=now)
            self.assertEqual(val['status'],'experimental_claim_model')
            self.assertEqual(val['events'],0)
            self.assertGreater(val['probability_of_observed_claim'],0)
            con.close()


class PipelineSourceHealth(unittest.TestCase):
    def test_source_health_and_no_compromise_claim(self):
        from threatwatch.feeds import Article
        from threatwatch.normalize import utc_now
        with tempfile.TemporaryDirectory() as tmp:
            con=connect(Path(tmp)/'db.sqlite')
            def fake(sources,orgs,delay=0):
                yield 'RansomLook — recent claims',[Article('Ransomware claim: EDF','Unverified actor claim',
                    'https://www.ransomlook.io/api/posts?days=7&ref=abc',utc_now(),
                    'RansomLook','ransomware-leak-monitors')],None
                yield 'Broken source',[],'network timeout'
            with patch('threatwatch.pipeline.collect_feeds',fake):
                result=run_once(con,organizations=load_organizations(),sources=[],delay=0)
            self.assertEqual(result['checked'],2)
            self.assertEqual(result['inserted'],1)
            self.assertEqual(con.execute("SELECT count(*) FROM source_checks WHERE status='ok'").fetchone()[0],1)
            self.assertEqual(con.execute("SELECT kind FROM items LIMIT 1").fetchone()['kind'],'claim')
            con.close()

if __name__=='__main__':
    unittest.main()

class CalibrationTests(unittest.TestCase):
    def test_temporal_validation_requires_labels(self):
        from threatwatch.calibration import temporal_holdout_report
        self.assertEqual(temporal_holdout_report([])['status'],'insufficient_labels')
    def test_temporal_validation_metrics(self):
        from threatwatch.calibration import temporal_holdout_report
        # Synthetic samples ONLY exercise calibration math, not real-world evidence.
        start=dt.date(2025,1,1)
        records=[]
        for i in range(150):
            label=1 if i%3==0 else 0
            features=[min(5,(2+label*2+(i%3)/4))]*8
            records.append((start+dt.timedelta(days=i),f'org{i}',features,label))
        report=temporal_holdout_report(records)
        self.assertEqual(report['status'],'evaluated_not_deployed')
        self.assertGreater(report['test_count'],15)
        self.assertIn('baseline_brier',report)
    def test_reject_future_label(self):
        from threatwatch.calibration import read_labelled_csv, FEATURES
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'history.csv'
            columns=['as_of_date','org_id','incident_next_14d']+list(FEATURES)
            path.write_text(','.join(columns)+'\n'+','.join(['2026-10-29','edf','1']+['1']*8)+'\n')
            with self.assertRaises(ValueError):
                read_labelled_csv(path,today=dt.date(2026,10,29))
