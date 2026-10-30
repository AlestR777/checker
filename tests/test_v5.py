"""v5: human extraction-quality audit + strict historical graph context tests."""
from __future__ import annotations
import csv
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from threatwatch.config import Organization
from threatwatch.store import connect,upsert_organizations,add_discovery,add_item
from threatwatch.entity_graph import discover_from_ledger,import_relations
from threatwatch.entity_quality import export_review_sample,evaluate_review_sample
from threatwatch.graph_temporal import graph_context_at,prepare_graph_history,GRAPH_FEATURES
from threatwatch.graph_model import validate_graph_history
from threatwatch.calibration import FEATURES
from threatwatch.cli import build_parser
from threatwatch.dashboard import quality_page,graph_page,org_page

DATE=dt.date(2026,10,25)

def ts(date):return date.isoformat()+'T09:00:00+00:00'

class V5GraphAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.con=connect(self.root/'test.sqlite')
        self.addCleanup(self.con.close)
        upsert_organizations(self.con,[
            Organization('a','Company A','Retail','FR',('Company A',)),
            Organization('b','Company B','Retail','FR',('Company B',)),
            Organization('c','Company C','Government','FR',('Company C',)),
            Organization('d','Company D','Retail','IT',('Company D',))])

    def add_news(self,org,article_date=DATE,seen_date=DATE,url='https://source.example.com/incident'):
        add_item(self.con,url=url,title='Claim about '+org,summary='Publicly claimed incident',
                 source_name='Cyber News',source_group='example.com',published_at=ts(article_date),
                 kind='claim',confidence=.5,rationale='claim, not confirmed',org_ids=[org])
        self.con.execute('UPDATE items SET collected_at=? WHERE url=?',(ts(seen_date),url))
        self.con.execute('UPDATE mentions SET linked_at=? WHERE org_id=?',(ts(seen_date),org))
        self.con.commit()

    def add_relation(self,left='a',right='b',status='verified',when=DATE):
        path=self.root/'relations.csv'
        path.write_text('source_org_id,target_org_id,relation_type,evidence_url,review_status\n'+
                        f'{left},{right},supplier,https://source.example.com/contract,{status}\n',encoding='utf-8')
        import_relations(self.con,path)
        self.con.execute("UPDATE organization_relations SET recorded_at=?,verified_at=CASE WHEN review_status='verified' THEN ? ELSE NULL END WHERE source_org_id=?",
                         (ts(when),ts(when),left))
        self.con.commit()

    def test_historical_graph_excludes_future_relationship(self):
        self.add_news('b')
        self.add_relation(when=DATE+dt.timedelta(days=2))
        result=graph_context_at(self.con,'a',DATE)
        self.assertEqual(result['documented_neighbors'],0)
        self.assertEqual(result['neighbor_claims_14d'],0)
        self.assertEqual(result['sector_claims_14d'],1)

    def test_historical_graph_only_verified_documented_relationships(self):
        self.add_news('b')
        self.add_relation(status='unverified',when=DATE-dt.timedelta(days=2))
        self.assertEqual(graph_context_at(self.con,'a',DATE)['documented_neighbors'],0)
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],0)
        self.con.execute("UPDATE organization_relations SET review_status='verified',verified_at=?",(ts(DATE),))
        self.con.commit()
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],1)
        self.assertEqual(graph_context_at(self.con,'a',DATE)['sector_claims_14d'],1)

    def test_historical_graph_never_uses_future_collected_or_linked_article(self):
        self.add_relation(when=DATE-dt.timedelta(days=1))
        self.add_news('b',article_date=DATE-dt.timedelta(days=2),seen_date=DATE+dt.timedelta(days=1))
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],0)
        self.con.execute('UPDATE items SET collected_at=?',(ts(DATE-dt.timedelta(days=1)),))
        self.con.commit()
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],0)
        self.con.execute('UPDATE mentions SET linked_at=?',(ts(DATE-dt.timedelta(days=1)),))
        self.con.commit()
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],1)

    def test_historical_graph_legacy_unknown_link_excluded(self):
        self.add_relation(when=DATE-dt.timedelta(days=1))
        self.add_news('b')
        self.con.execute('UPDATE mentions SET linked_at=NULL')
        self.con.commit()
        self.assertEqual(graph_context_at(self.con,'a',DATE)['neighbor_claims_14d'],0)

    def test_source_claim_never_becomes_attack_confirmation(self):
        self.add_news('b')
        state=graph_context_at(self.con,'a',DATE)
        self.assertEqual(state['country_claims_14d'],1)
        self.assertIn('not successful compromises',state['limitations'])

    def test_entity_sampling_includes_unmatched_and_does_not_prelabel(self):
        add_discovery(self.con,url='https://news.example.org/a',title='Ransomware claim: Sample Corporation',
                      summary='country: France; sector: Energy',source_name='Aggregator',source_group='agg',
                      published_at=ts(DATE),kind='claim',candidate_name='Sample Corporation')
        add_discovery(self.con,url='https://news.example.org/b',title='Other story with Company Z',
                      summary='No structured entity',source_name='News',source_group='news',
                      published_at=ts(DATE),kind='incident_report',candidate_name='')
        discover_from_ledger(self.con)
        output=self.root/'audit.csv'
        result=export_review_sample(self.con,output,size=10)
        self.assertEqual(result['rows'],2)
        with output.open(encoding='utf-8-sig') as fp: rows=list(csv.DictReader(fp))
        self.assertEqual({r['expected_organizations'] for r in rows},{''})
        self.assertEqual(sum(bool(r['predicted_organizations']) for r in rows),1)
        self.assertEqual(result['without_predictions'],1)
        self.assertIn('Качество извлечения',quality_page(self.con).decode())

    def test_audit_precision_recall_and_unreviewed_are_not_zero(self):
        output=self.root/'reviewed.csv'
        rows=[{'url_key':'a','url':'https://news.example.org/a','published_at':ts(DATE),
               'source_name':'News','title':'A story','summary':'',
               'predicted_organizations':'Company A | Company B',
               'reviewed':'yes','expected_organizations':'Company A | Company C',
               'reviewer_notes':'Completed'},
              {'url_key':'b','url':'https://news.example.org/b','published_at':ts(DATE),
               'source_name':'News','title':'Another story','summary':'',
               'predicted_organizations':'Company D',
               'reviewed':'','expected_organizations':'NONE',
               'reviewer_notes':''}]
        with output.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
        result=evaluate_review_sample(output,minimum=1)
        self.assertEqual(result['status'],'measured')
        self.assertEqual((result['tp'],result['fp'],result['fn']),(1,1,1))
        self.assertEqual(result['precision'],.5)
        self.assertEqual(result['recall'],.5)
        self.assertEqual(result['skipped_unreviewed'],1)

    def test_audit_review_needs_annotation(self):
        f=self.root/'audit.csv'
        f.write_text('url_key,url,published_at,source_name,title,summary,predicted_organizations,reviewed,expected_organizations,reviewer_notes\n'
                     'aaa,https://example.org/a,2026-10-01,X,T,S,,yes,,\n',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'exhaustive'):
            evaluate_review_sample(f)

    def test_prepare_graph_history_unlabelled_and_conservative(self):
        start=dt.date(2026,8,1)
        for day in range(42):
            when=start+dt.timedelta(days=day)
            for group in ('a','b'):
                self.con.execute('''INSERT INTO source_checks(checked_at,source_name,source_group,status,fetched,error)
                        VALUES(?,?,?,?,?,?)''',(ts(when),group,group,'ok',1,''))
        self.con.commit()
        self.add_news('b',article_date=dt.date(2026,8,29),seen_date=dt.date(2026,8,29))
        path=self.root/'graph_history.csv'
        result=prepare_graph_history(self.con,path,start='2026-09-08',end='2026-09-08',today=dt.date(2026,10,1))
        self.assertEqual(result['status'],'candidate_snapshots_unlabelled')
        self.assertEqual(result['rows'],4)
        with path.open(encoding='utf-8-sig') as fp: rows=list(csv.DictReader(fp))
        self.assertEqual(rows[0]['snapshot_mode'],'strict_observed')
        self.assertEqual(rows[0]['incident_next_14d'],'')
        self.assertIn('neighbor_claims_14d',rows[0])

    def test_graph_model_needs_verified_outcomes(self):
        path=self.root/'graph_history.csv'
        row={'as_of_date':'2026-08-01','org_id':'a',
             **{f:'0' for f in FEATURES},**{g:'0' for g in GRAPH_FEATURES},
             'incident_next_14d':'','label_status':'UNLABELLED_REQUIRES_INDEPENDENT_REVIEW',
             'outcome_evidence_url':'','outcome_notes':'',
             'observed_until':'2026-08-15','snapshot_mode':'strict_observed'}
        with path.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,row.keys());w.writeheader();w.writerow(row)
        with self.assertRaisesRegex(ValueError,'independent human verification|invalid literal'):
            validate_graph_history(path,today=dt.date(2026,10,1))

    def test_graph_model_comparison_runs_only_on_independently_reviewed_history(self):
        from threatwatch.graph_temporal import GRAPH_FIELDS
        path=self.root/'labelled_synthetic_for_test_only.csv'
        rows=[]
        start=dt.date(2026,1,4)
        for week in range(18):
            date=start+dt.timedelta(days=7*week)
            for org_i in range(10):
                label=int((week+org_i)%3==0)
                row={'as_of_date':date.isoformat(),'org_id':f'test-org-{org_i}',
                    **{feature:str((week+org_i)%5) for feature in FEATURES},
                    **{feature:str((label*3+org_i+week)%6) for feature in GRAPH_FEATURES},
                    'incident_next_14d':str(label),'label_status':'verified',
                    'outcome_evidence_url':'https://audit.example.org/independent-review',
                    'outcome_notes':'SYNTHETIC DATA TEST ONLY',
                    'observed_until':(date+dt.timedelta(days=14)).isoformat(),
                    'snapshot_mode':'strict_observed'}
                rows.append(row)
        with path.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=GRAPH_FIELDS);w.writeheader();w.writerows(rows)
        result=validate_graph_history(path,today=dt.date(2027,1,1))
        self.assertEqual(result['status'],'evaluated_not_deployed')
        self.assertGreater(result['train_snapshots'],40)
        self.assertGreater(result['test_snapshots'],15)
        self.assertIn('direct_signals_brier',result)
        self.assertIn('direct_plus_graph_brier',result)
        self.assertEqual(result['embargo_days'],14)
        self.assertNotIn('organization_probabilities',result)

    def test_dashboard_and_new_cli(self):
        parsed=build_parser().parse_args(['export-entity-audit','audit.csv','--size','20'])
        self.assertEqual(parsed.size,20)
        self.assertEqual(build_parser().parse_args(['graph-context','a']).org_id,'a')
        self.assertIn('Граф',graph_page(self.con,{'org_id':['a']}).decode())
        self.assertIn('Подробнее о связях',org_page(self.con,'a').decode())

    def test_migration_old_mentions_and_candidates(self):
        import sqlite3
        path=self.root/'legacy.sqlite'
        con=sqlite3.connect(path)
        con.executescript('''CREATE TABLE mentions(item_id INTEGER, org_id TEXT, PRIMARY KEY(item_id,org_id));
             CREATE TABLE entity_candidates(id INTEGER PRIMARY KEY,name_key TEXT NOT NULL UNIQUE,name TEXT NOT NULL,
             country TEXT NOT NULL DEFAULT '',sector TEXT NOT NULL DEFAULT '',status TEXT NOT NULL DEFAULT 'pending',
             first_seen TEXT NOT NULL,last_seen TEXT NOT NULL,detection_method TEXT NOT NULL,
             reviewed_org_id TEXT NOT NULL DEFAULT '');''')
        con.close()
        con=connect(path)
        self.assertIn('linked_at',{r[1] for r in con.execute('PRAGMA table_info(mentions)')})
        self.assertIn('reviewed_at',{r[1] for r in con.execute('PRAGMA table_info(entity_candidates)')})
        con.close()

if __name__=='__main__':unittest.main()
