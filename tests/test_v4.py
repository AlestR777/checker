"""Incident-first ingestion, graph provenance, filters and optional model safeguards."""
from __future__ import annotations
import datetime as dt
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit
from threatwatch.store import connect, upsert_organizations, add_discovery, add_item
from threatwatch.config import Organization
from threatwatch.normalize import utc_now
from threatwatch.entity_graph import (discover_from_ledger,extract_explicit_victim,explicit_metadata,
    list_candidates,approve_candidate,reject_candidate,runtime_organizations,import_relations,
    organization_connections,entity_key)
from threatwatch.dashboard import home,candidates_page,org_page
from threatwatch.gdelt import query_url,parse_articles
from threatwatch.wikidata_relations import extract_relationship_qids,suggest_wikidata_links
from threatwatch.cli import build_parser

class V4Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.con=connect(Path(self.tmp.name)/'test.db')
        self.addCleanup(self.con.close)
        self.org=Organization('demo','Demo Public Company','Healthcare','FR',('Demo Public Company',))
        self.other=Organization('other','Another Company','Healthcare','FR',('Another Company',))
        upsert_organizations(self.con,[self.org,self.other])

    def discovery(self,name='Sample Co',date=None,url='https://example.org/a'):
        return add_discovery(self.con,url=url,title=f'Ransomware claim: {name}',
            summary='Unverified ransomware listing; group: actor; country: France; sector: Transport. Source: Ransomfeed public metadata.',
            source_name='Ransomfeed',source_group='ransomware-leak-monitors',
            published_at=date or utc_now(),kind='claim',candidate_name=name)

    def test_explicit_is_not_any_headline(self):
        self.assertEqual(extract_explicit_victim('Ransomware claim: Sample Co'),'Sample Co')
        self.assertIsNone(extract_explicit_victim('Paris government website inaccessible'))
        self.assertIsNone(extract_explicit_victim('Ransomware claim: France'))

    def test_metadata_country_is_explicit_not_inferred(self):
        self.assertEqual(explicit_metadata('country: France; sector: Retail.'),('FR','Retail'))
        self.assertEqual(explicit_metadata('There was news in France'),('',''))

    def test_discovery_dedup_and_filters(self):
        self.discovery()
        result=discover_from_ledger(self.con)
        self.assertEqual(result['new_evidence'],1)
        self.assertEqual(discover_from_ledger(self.con)['new_evidence'],0)
        rows=list_candidates(self.con,country='FR',sector='Transport')
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['publications'],1)
        self.assertEqual(list_candidates(self.con,country='IT'),[])

    def test_approval_links_existing_evidence(self):
        self.discovery()
        discover_from_ledger(self.con)
        r=approve_candidate(self.con,1,country='IT',sector='Transport')
        self.assertTrue(r['organization_id'].startswith('discovered-'))
        self.assertEqual(r['linked_publications'],1)
        items=self.con.execute('''SELECT i.source_group,m.org_id FROM items i
           JOIN mentions m ON m.item_id=i.id WHERE m.org_id=?''',(r['organization_id'],)).fetchall()
        self.assertEqual(items[0]['source_group'],'ransomware-leak-monitors')
        merged=runtime_organizations(self.con,[self.org,self.other])
        self.assertEqual(len(merged),3)
        self.assertEqual(merged[-1].country,'IT')
        self.assertEqual(approve_candidate(self.con,1,country='IT',sector='Transport')['linked_publications'],0)
        self.assertIn('Sample Co',org_page(self.con,r['organization_id']).decode())

    def test_reject_and_prevent_approval(self):
        self.discovery();discover_from_ledger(self.con);reject_candidate(self.con,1)
        self.assertEqual(len(list_candidates(self.con,status='pending')),0)
        with self.assertRaises(ValueError): approve_candidate(self.con,1,country='FR',sector='Retail')

    def test_review_requires_country_sector(self):
        self.discovery();discover_from_ledger(self.con)
        with self.assertRaises(ValueError):approve_candidate(self.con,1,country='',sector='Retail')
        with self.assertRaises(ValueError):approve_candidate(self.con,1,country='FR',sector='')

    def test_page_filters_are_escaped(self):
        filtered=home(self.con,{'country':['IT'],'sector':['Retail']}).decode()
        self.assertIn('Нет организаций с такими фильтрами',filtered)
        self.assertNotIn('Demo Public Company</strong>',filtered)
        self.discovery(name='<script>')
        discover_from_ledger(self.con)
        rendered=candidates_page(self.con,{}).decode()
        self.assertNotIn('<script>',rendered)

    def test_directed_relations_require_provenance(self):
        p=Path(self.tmp.name)/'relations.csv'
        p.write_text('source_org_id,target_org_id,relation_type,evidence_url,review_status\n'
             'demo,other,supplier,https://example.org/source,verified\n'
             'demo,other,parent,not-a-url,verified\n',encoding='utf8')
        result=import_relations(self.con,p)
        self.assertEqual(result['inserted'],1)
        self.assertEqual(len(result['errors']),1)
        connections=organization_connections(self.con,'demo')
        self.assertEqual(connections['documented'][0]['relation_type'],'supplier')
        self.assertEqual(connections['similar'][0]['name'],'Another Company')

    def test_co_mentions_not_pretended_contractual_relationship(self):
        add_item(self.con,url='https://example.org/story',title='Ransomware report about Demo Public Company and Another Company',
            summary='Multiple organizations mentioned',source_name='Publication',source_group='example.org',
            published_at=utc_now(),kind='incident_report',confidence=.4,rationale='Reported claim',org_ids=['demo','other'])
        c=organization_connections(self.con,'demo')
        self.assertEqual(len(c['co_mentioned']),1)
        self.assertEqual(c['documented'],[])
        self.assertIn('Упомянуты вместе',org_page(self.con,'demo').decode())

    def test_gdelt_metadata_cannot_locate_target(self):
        url=query_url('ransomware OR cyberattack',limit=40,timespan='7d')
        self.assertEqual(urlsplit(url).hostname,'api.gdeltproject.org')
        art=parse_articles({'articles':[{'title':'Cyberattack reported at Sample Co',
            'url':'https://news.example.com/story','seendate':'20261029T120000Z','sourcecountry':'France'}]})
        self.assertEqual(len(art),1)
        self.assertTrue(art[0].published_at.startswith('2026-10-29T12:00'))
        self.assertIn('Country of publication',art[0].summary)
        self.assertNotIn('victim country: France',art[0].summary)

    def test_wikidata_relations_are_only_suggestions(self):
        entity={'claims':{'P749':[{'rank':'normal','mainsnak':{'datavalue':{'value':{'id':'Q42'}}}}],
                          'P355':[{'rank':'deprecated','mainsnak':{'datavalue':{'value':{'id':'Q99'}}}}]}}
        self.assertEqual(extract_relationship_qids(entity),[{'target_qid':'Q42','relation_type':'parent','property':'P749'}])
        first={'labels':{'en':{'value':'Demo Public Company'}},**entity}
        second={'labels':{'en':{'value':'Parent Organization'}},'claims':{}}
        with patch('threatwatch.wikidata_relations.get_qid_data',side_effect=[first,second]):
            result=suggest_wikidata_links(self.con,'demo','Q12')
        self.assertEqual(result['suggestions'][0]['status'],'pending_review')
        self.assertEqual(len(list_candidates(self.con)),1)
        self.assertFalse(organization_connections(self.con,'demo')['documented'])

    def test_headline_discovery_without_ai(self):
        from threatwatch.entity_graph import extract_headline_subject
        self.assertEqual(extract_headline_subject('Alpine Hospital hit by ransomware on Friday'),'Alpine Hospital')
        self.assertEqual(extract_headline_subject('Société Centrale victime d’une cyberattaque en octobre'),'Société Centrale')
        self.assertIsNone(extract_headline_subject('Ransomware statistics in Europe rose'))
        add_discovery(self.con,url='https://news.example.com/incident',
            title='Alpine Hospital hit by ransomware on Friday',summary='Public media report',
            source_name='News',source_group='news.example.com',published_at=utc_now(),kind='incident_report')
        result=discover_from_ledger(self.con)
        self.assertEqual(result['new_evidence'],1)
        self.assertEqual(list_candidates(self.con)[0]['detection_method'],'headline_subject_heuristic')

    def test_manual_incident_import_and_statistical_filters(self):
        from threatwatch.cli import import_incident_csv
        from threatwatch.dashboard import incidents_page,analytics_page
        p=Path(self.tmp.name)/'manual.csv'
        p.write_text('url,title,summary,published_at,source_name,source_group,kind,candidate_name\n'
           'https://news.example.com/1,Public cyberattack report,Incident summary,2026-10-28T10:00:00Z,Daily,news.example.com,incident_report,Retail Chain Z\n',
           encoding='utf8')
        out=import_incident_csv(self.con,p)
        self.assertEqual(out['inserted'],1)
        self.assertEqual(out['entity_discovery']['new_evidence'],1)
        self.assertIn('Public cyberattack report',incidents_page(self.con,{}).decode())
        self.assertIn('По странам',analytics_page(self.con).decode())

    def test_pipeline_automatically_discovers_new_entity_offline(self):
        from threatwatch.pipeline import run_once
        from threatwatch.feeds import Article
        incoming=Article(title='Ransomware claim: Harborline Services',
            summary='Unverified ransomware listing; group: test; country: France; sector: Transport.',
            url='https://api.example.org/claim',published_at=utc_now(),
            source_name='RansomLook',source_group='ransomware-leak-monitors')
        with patch('threatwatch.pipeline.collect_feeds',return_value=[('RansomLook',[incoming],None)]):
            out=run_once(self.con,organizations=[self.org,self.other],sources=[],delay=0)
        self.assertEqual(out['pending_candidates'],1)
        self.assertEqual(out['new_candidate_evidence'],1)
        self.assertEqual(len(list_candidates(self.con)),1)
        self.assertFalse(out.get('local_ai_suggestions'))

    def test_imported_links_and_candidate_export(self):
        from threatwatch.cli import export
        self.discovery()
        discover_from_ledger(self.con)
        p=Path(self.tmp.name)/'entities.json'
        self.assertEqual(export(self.con,p,'entities'),1)
        self.assertEqual(json.loads(p.read_text(encoding='utf8'))[0]['name'],'Sample Co')

    def test_ransomwhere_claim_metadata_not_confirmed(self):
        from threatwatch.ransomwhere import parse_victims
        rows=parse_victims([{'victim':'Fictional Transport','group':'ExampleActor',
            'country':'FR','sector':'Transport','discovered':'2026-10-29T12:00:00Z'}])
        self.assertEqual(len(rows),1)
        self.assertIn('country: FR; sector: Transport',rows[0].summary)
        self.assertEqual(rows[0].source_group,'ransomware-leak-monitors')
        self.assertIn('Unverified',rows[0].summary)

    def test_api_analytics_and_country_filter_reject_unknown(self):
        from threatwatch.analytics import aggregate
        from threatwatch.dashboard import incidents_page
        self.discovery()
        discover_from_ledger(self.con)
        overview=aggregate(self.con)
        self.assertEqual(overview['countries'][0]['label'],'FR')
        html=incidents_page(self.con,{'country':['FR'],'kind':['claim']}).decode()
        self.assertIn('Ransomware claim: Sample Co',html)
        self.assertNotIn('Ransomware claim: Sample Co',incidents_page(self.con,{'country':['DE']}).decode())

    def test_old_db_schema_migration_preserves_existing_evidence(self):
        from threatwatch.entity_graph import ensure_schema
        self.discovery()
        before=self.con.execute('SELECT count(*) FROM discovery').fetchone()[0]
        ensure_schema(self.con)
        self.assertEqual(self.con.execute('SELECT count(*) FROM discovery').fetchone()[0],before)

    def test_new_cli_subcommands(self):
        p=build_parser()
        self.assertEqual(p.parse_args(['entities','--country','FR']).command,'entities')
        self.assertEqual(p.parse_args(['enrich-wikidata','demo','Q123']).qid,'Q123')

if __name__=='__main__':unittest.main()
