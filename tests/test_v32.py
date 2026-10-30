"""Offline regression tests of v3.2 chronology, local-AI opt in and Cybermap."""
from __future__ import annotations
import csv
import datetime as dt
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from threatwatch.cli import build_parser,main
from threatwatch.config import load_organizations,load_sources
from threatwatch.store import connect,upsert_organizations,add_item
from threatwatch.history import point_in_time_features,prepare_history,FIELDS
from threatwatch.cybermap import import_observations,recent_observations,WIDGET_URL
from threatwatch.dashboard import cybermap_page,make_handler
from threatwatch.calibration import read_labelled_csv,FEATURES

D=dt.date

def mkdate(d):return d.isoformat()+'T12:00:00+00:00'

class V32Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.dir=Path(self.tmp.name)
        self.con=connect(self.dir/'test.sqlite')
        upsert_organizations(self.con,load_organizations())
    def tearDown(self):
        self.con.close();self.tmp.cleanup()
    def test_optional_ai_flags_default_off_and_available(self):
        args=build_parser().parse_args(['run'])
        self.assertFalse(args.ai);self.assertFalse(args.local_ai);self.assertFalse(args.ml)
        self.assertEqual(args.local_ai_limit,5)
        args=build_parser().parse_args(['watch','--local-ai','--local-ai-limit','8'])
        self.assertTrue(args.local_ai);self.assertEqual(args.local_ai_limit,8)
        args=build_parser().parse_args(['run','--local-ai'])
        self.assertTrue(args.local_ai)
    def test_run_default_never_calls_ollama(self):
        from threatwatch.pipeline import run_once
        with patch('threatwatch.pipeline.collect_feeds',return_value=iter([])),\
             patch('threatwatch.local_ai.triage_discovery') as local:
            result=run_once(self.con,organizations=load_organizations(),sources=[],delay=0)
        self.assertNotIn('local_ai_suggestions',result);local.assert_not_called()
    def add_real_item(self, published:dt.date, collected:dt.date, name='edf', idx=1,kind='claim'):
        add_item(self.con,url=f'https://news.example.org/story-{idx}',title=f'Story {idx} EDF',summary='report',
                 source_name='News',source_group='news.test',published_at=mkdate(published),
                 kind=kind,confidence=.6,rationale='test',org_ids=[name])
        self.con.execute('UPDATE items SET collected_at=? WHERE url=?',(mkdate(collected),f'https://news.example.org/story-{idx}'))
        self.con.commit()
    def test_reject_hindsight_article_collected_after_asof(self):
        self.add_real_item(D(2026,10,6),D(2026,10,29),idx=1)
        self.assertEqual(point_in_time_features(self.con,'edf',D(2026,10,12)),[0]*8)
        self.assertNotEqual(point_in_time_features(self.con,'edf',D(2026,10,12),mode='retrospective'),[0]*8)
    def test_strict_uses_only_observed_publications(self):
        self.add_real_item(D(2026,10,7),D(2026,10,8),idx=1,kind='threat_statement')
        self.add_real_item(D(2026,10,9),D(2026,10,20),idx=2)
        vals=point_in_time_features(self.con,'edf',D(2026,10,12))
        self.assertEqual(vals[0],2);self.assertEqual(vals[1],0)
        self.assertEqual(vals[-1],0)  # review date unknown in old database
    def test_no_history_without_monitoring(self):
        f=self.dir/'labels.csv'
        res=prepare_history(self.con,f,start='2026-10-01',end='2026-10-15',today=D(2026,11,1))
        self.assertEqual(res['rows'],0)
        self.assertEqual(len(f.read_text(encoding='utf-8-sig').splitlines()),1)
    def test_can_create_point_in_time_history_with_monitoring(self):
        start=D(2026,8,1)
        for day in range(40):
            date=start+dt.timedelta(days=day)
            self.con.execute('INSERT INTO source_checks(checked_at,source_name,source_group,status,fetched,error) '
                             'VALUES (?,?,?,?,?,?)',(mkdate(date),'S1','independent-a','ok',1,''))
            self.con.execute('INSERT INTO source_checks(checked_at,source_name,source_group,status,fetched,error) '
                             'VALUES (?,?,?,?,?,?)',(mkdate(date),'S2','independent-b','ok',1,''))
        self.con.commit()
        self.add_real_item(D(2026,8,25),D(2026,8,25),idx=12)
        target=self.dir/'labels.csv'
        out=prepare_history(self.con,target,start='2026-09-02',end='2026-09-02',today=D(2026,10,1))
        self.assertEqual(out['rows'],len(load_organizations()))
        with target.open(encoding='utf-8-sig') as f: rows=list(csv.DictReader(f))
        self.assertEqual(len(rows),len(load_organizations()))
        self.assertTrue(all(not r['incident_next_14d'] for r in rows))
        self.assertTrue(all(r['snapshot_mode']=='strict_observed' for r in rows))
    def test_labelled_csv_requires_review_provenance(self):
        f=self.dir/'labels.csv'
        row={'as_of_date':'2026-08-01','org_id':'edf','incident_next_14d':'0',
             'label_status':'UNLABELLED_REQUIRES_INDEPENDENT_REVIEW',
             'outcome_evidence_url':'','snapshot_mode':'strict_observed',
             **{feature:'0' for feature in FEATURES}}
        with f.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=row);w.writeheader();w.writerow(row)
        with self.assertRaisesRegex(ValueError,'independent human verification'):
            read_labelled_csv(f,today=D(2026,10,1))
        row.update(label_status='verified',outcome_evidence_url='https://audit.example.org/report')
        with f.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=row);w.writeheader();w.writerow(row)
        self.assertEqual(len(read_labelled_csv(f,today=D(2026,10,1))),1)
        row['snapshot_mode']='retrospective_not_for_training'
        with f.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=row);w.writeheader();w.writerow(row)
        with self.assertRaisesRegex(ValueError,'Retrospective'):
            read_labelled_csv(f,today=D(2026,10,1))
    def test_cybermap_import_validation_and_display(self):
        f=self.dir/'observations.csv'
        rows=[{'observed_date':'2026-10-10','country':'France','category':'RMW',
               'measurement':'Share of detection events in displayed country listing',
               'value':'2.8','unit':'%','source_url':'https://cybermap.kaspersky.com/ru/stats',
               'analyst_note':'Example for test only; never a real figure'}]
        with f.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=rows[0]);w.writeheader();w.writerows(rows)
        self.assertEqual(import_observations(self.con,f,today=D(2026,10,29))['inserted'],1)
        self.assertEqual(import_observations(self.con,f,today=D(2026,10,29))['duplicates'],1)
        self.assertEqual(recent_observations(self.con)[0]['category'],'RMW')
        self.assertIn('RMW',cybermap_page(self.con).decode())
        self.assertIn('frame',cybermap_page(self.con).decode())
        self.assertIn('cybermap.kaspersky.com/ru/widget',cybermap_page(self.con).decode())
        self.assertEqual(self.con.execute('select count(*) from items').fetchone()[0],0)
    def test_import_rejects_malicious_url(self):
        f=self.dir/'bad.csv'
        row=dict(zip(('observed_date','country','category','measurement','value','unit','source_url','analyst_note'),
                     ('2026-10-10','France','IDS','Test',3,'count','https://example.org/','')))
        with f.open('w',encoding='utf-8',newline='') as fp:
            w=csv.DictWriter(fp,fieldnames=row);w.writeheader();w.writerow(row)
        out=import_observations(self.con,f,today=D(2026,10,29))
        self.assertEqual(out['inserted'],0)
        self.assertIn('Kaspersky',out['errors'][0])
    def test_kaspersky_sources_configured(self):
        src={s['id'] for s in load_sources(include_disabled=True)}
        self.assertIn('kaspersky-securelist-en',src)
        # Russian mirror is known to terminate TLS unexpectedly and is disabled by default.
        import json
        from threatwatch.config import ROOT
        raw=json.loads((ROOT/'sources.json').read_text(encoding='utf-8'))
        ru=next(x for x in raw if x['id']=='kaspersky-securelist-ru')
        self.assertFalse(ru['enabled'])
        self.assertIn('/ru/widget/dynamic/dark',WIDGET_URL)

if __name__=='__main__':unittest.main()

class CLIRegressionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.db=Path(self.temp.name)/'cli.db'
    def tearDown(self):self.temp.cleanup()
    def test_cli_run_without_ai_never_reads_missing_attribute(self):
        from contextlib import redirect_stdout
        import io
        with patch('threatwatch.cli.run_once',return_value={'checked':0,'fetched':0,'errors':[]}) as run, \
             redirect_stdout(io.StringIO()):
            main(['--db',str(self.db),'run'])
        self.assertFalse(run.call_args.kwargs['ai'])
        self.assertFalse(run.call_args.kwargs['local_ai'])
    def test_cli_run_local_ai_opt_in(self):
        from contextlib import redirect_stdout
        import io
        with patch('threatwatch.cli.run_once',return_value={'checked':0,'fetched':0,'errors':[]}) as run, \
             redirect_stdout(io.StringIO()):
            main(['--db',str(self.db),'run','--local-ai','--local-ai-limit','3'])
        self.assertTrue(run.call_args.kwargs['local_ai'])
        self.assertEqual(run.call_args.kwargs['local_ai_limit'],3)
    def test_mutually_exclusive_ai(self):
        from contextlib import redirect_stdout
        import io
        with redirect_stdout(io.StringIO()), self.assertRaisesRegex(ValueError,'Choose --ai or --local-ai'):
            main(['--db',str(self.db),'run','--ai','--local-ai'])
