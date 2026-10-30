"""Multilingual entities and lossless relationship suggestions."""
import datetime as dt
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from threatwatch.config import Organization
from threatwatch.entity_graph import (
    approve_candidate, discover_from_ledger, eligible_name, entity_key,
    extract_headline_subject, list_candidates, network_context, organization_connections,
)
from threatwatch.normalize import classify_rule, matching_organizations, plain, title_similarity, utc_now
from threatwatch.store import add_discovery, add_item, connect, review_item, upsert_organizations
from threatwatch.wikidata_relations import suggest_wikidata_links


class MultilingualTests(unittest.TestCase):
    def test_non_latin_names_remain_distinct(self):
        self.assertEqual(plain('Électricité Ёлка'), 'electricite елка')
        for name in ('Сбербанк', 'Газпром', '腾讯', 'トヨタ自動車', '삼성전자'):
            self.assertTrue(eligible_name(name), name)
            self.assertTrue(entity_key(name), name)
        self.assertNotEqual(entity_key('Сбербанк'), entity_key('Газпром'))
        self.assertNotEqual(entity_key('ドコモ'), entity_key('トコモ'))
        self.assertEqual(plain('Йошкар-Ола'), 'йошкар-ола')
        self.assertFalse(eligible_name('123456'))

    def test_non_latin_matching_and_word_boundaries(self):
        orgs = [Organization('sber','Сбербанк','finance','RU',('Сбербанк',)),
                Organization('gas','Газпром','energy','RU',('Газпром',)),
                Organization('qq','腾讯','tech','CN',('腾讯',)),
                Organization('toyota','トヨタ自動車','auto','JP',('トヨタ自動車',))]
        self.assertEqual(matching_organizations('Сбербанк подтвердил утечку данных', orgs), ['sber'])
        self.assertEqual(matching_organizations('Обсуждают Сбербанковский сервис', orgs), [])
        self.assertEqual(matching_organizations('腾讯公司遭遇网络攻击', orgs), ['qq'])
        self.assertEqual(matching_organizations('トヨタ自動車がサイバー攻撃を確認', orgs), ['toyota'])

    def test_titles_do_not_collapse_to_empty_ascii(self):
        self.assertLess(title_similarity('Взлом Сбербанка', 'Утечка Газпрома'), .8)
        self.assertGreater(title_similarity('Утечка данных Сбербанка', 'Сбербанка данных утечка'), .99)
        self.assertEqual(title_similarity('!!!', '???'), 0)

    def test_explicit_threat_vs_general_discussion(self):
        self.assertEqual(classify_rule('Хакеры угрожают кибератакой компании', '')[0], 'threat_statement')
        self.assertEqual(classify_rule('Компания подтвердила кибератаку', '')[0], 'incident_report')
        self.assertEqual(classify_rule('Hacktivist cyber activity trends', '')[0], 'context')
        self.assertEqual(classify_rule('Компания подтвердила утечку данных', '')[0], 'incident_report')
        self.assertEqual(classify_rule('Sicherheitsbericht: Datenleck bei Firma', '')[0], 'incident_report')

    def test_explicit_incidents_override_cve_context(self):
        for title in (
            'Microsoft confirms data breach after attackers exploited CVE-2026-12345',
            'Toyota suffers cyberattack',
            'Samsung Electronics hit by ransomware',
            'Toyota suffered a cyber attack after CVE-2026-12345 exploitation',
            'Компания подтвердила утечку данных после эксплуатации CVE-2026-12345',
        ):
            with self.subTest(title=title):
                self.assertEqual(classify_rule(title,'')[0], 'incident_report')

    def test_generic_vulnerability_warning_is_not_incident(self):
        for title in (
            'Microsoft issues security advisory for CVE-2026-12345',
            'Microsoft warns CVE-2026-12345 could cause a data breach',
            'Company confirms a vulnerability may lead to ransomware: CVE-2026-12345',
            'Microsoft has not confirmed data breach related to CVE-2026-12345',
        ):
            with self.subTest(title=title):
                self.assertEqual(classify_rule(title,'')[0], 'advisory')
        self.assertEqual(classify_rule('Toyota discusses cyberattack risk management','')[0], 'context')

    def test_russian_incident_subject_is_only_candidate(self):
        self.assertEqual(extract_headline_subject('Сбербанк подтвердил утечку данных клиентов'), 'Сбербанк')
        self.assertEqual(extract_headline_subject('Газпром подвергся кибератаке'), 'Газпром')
        self.assertIsNone(extract_headline_subject('В России выросло число кибератак'))


class RelationPersistenceTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.con = connect(Path(folder.name) / 'test.db')
        self.addCleanup(self.con.close)
        upsert_organizations(self.con, [Organization('source','Источник','tech','RU',('Источник',))])
        self.source = {'labels': {'ru': {'value':'Источник'}}, 'claims': {'P749': [
            {'rank':'normal', 'mainsnak': {'datavalue': {'value': {'id':'Q22'}}}}
        ]}}
        self.target = {'labels': {'ru': {'value':'Родительская компания'}}}

    def test_pending_relation_survives_entity_approval_and_rerun(self):
        with patch('threatwatch.wikidata_relations.get_qid_data', side_effect=[self.source,self.target]):
            result = suggest_wikidata_links(self.con, 'source', 'Q11')
        self.assertEqual(result['suggestions'][0]['status'], 'pending_review')
        before = organization_connections(self.con, 'source')
        self.assertEqual(before['documented'], [])
        self.assertEqual(before['summary']['state'], 'pending_review')
        candidate_id = before['pending'][0]['target_candidate_id']
        approved = approve_candidate(self.con, candidate_id, country='RU', sector='tech')
        self.assertTrue(approved['organization_id'].isascii())
        after = organization_connections(self.con, 'source')
        self.assertEqual(len(after['documented']), 1)
        relation = after['documented'][0]
        self.assertEqual(relation['review_status'], 'unverified')
        self.assertIsNone(relation['verified_at'])
        self.assertEqual(relation['evidence_url'], 'https://www.wikidata.org/wiki/Q11')
        self.assertEqual(after['pending'], [])
        approve_candidate(self.con, candidate_id, country='RU', sector='tech')
        with patch('threatwatch.wikidata_relations.get_qid_data', side_effect=[self.source,self.target]):
            suggest_wikidata_links(self.con, 'source', 'Q11')
        self.assertEqual(len(organization_connections(self.con, 'source')['documented']), 1)

    def test_wikidata_matches_label_translation_or_exact_declared_alias(self):
        self.source['labels'] = {'en': {'value':'Source Company'}, 'ru': {'value':'Источник'}}
        upsert_organizations(self.con, [Organization('target','親会社','tech','JP',('親会社',))])
        self.target['labels'] = {'en': {'value':'Parent Company'}, 'ja': {'value':'親会社'}}
        with patch('threatwatch.wikidata_relations.get_qid_data', side_effect=[self.source,self.target]):
            result = suggest_wikidata_links(self.con, 'source', 'Q11')
        self.assertEqual(result['suggestions'][0]['status'], 'unverified_link')
        self.assertEqual(organization_connections(self.con, 'source')['documented'][0]['other_id'], 'target')
        self.assertEqual(list_candidates(self.con), [])

    def test_ambiguous_identity_does_not_create_relation(self):
        upsert_organizations(self.con, [Organization('a','Parent Company','tech','US',('Parent Company',)),
                                      Organization('b','Parent Company','tech','GB',('Parent Company',))])
        self.target = {'labels': {'en': {'value':'Parent Company'}}}
        with patch('threatwatch.wikidata_relations.get_qid_data', side_effect=[self.source,self.target]):
            result = suggest_wikidata_links(self.con, 'source', 'Q11')
        self.assertEqual(result['suggestions'][0]['status'], 'ambiguous_identity')
        self.assertEqual(organization_connections(self.con, 'source')['documented'], [])

    def test_rejected_publication_is_not_a_graph_link(self):
        upsert_organizations(self.con, [Organization('other','Другая компания','tech','RU',('Другая компания',))])
        add_item(self.con, url='https://news.test/1', title='Источник и Другая компания', summary='',
                 source_name='News', source_group='news.test', published_at=utc_now(), kind='claim',
                 confidence=.5, rationale='Test', org_ids=['source','other'])
        self.assertEqual(len(organization_connections(self.con,'source')['co_mentioned']), 1)
        item = self.con.execute('SELECT id FROM items').fetchone()[0]
        review_item(self.con, item, 'rejected')
        self.assertEqual(organization_connections(self.con,'source')['co_mentioned'], [])
        self.assertEqual(organization_connections(self.con,'source')['summary']['state'], 'no_documented_links')

    def test_discovery_keeps_cyrillic_entities_distinct(self):
        for index, name in enumerate(('Банк Пример','Компания Пример')):
            add_discovery(self.con, url=f'https://news.test/{index}', title='Ransomware claim: '+name,
                          summary='', source_name='News', source_group='news.test', published_at=utc_now(),
                          kind='claim', candidate_name=name)
        discover_from_ledger(self.con)
        self.assertEqual({x['name'] for x in list_candidates(self.con)}, {'Банк Пример','Компания Пример'})


class ExplicitRelationDiscoveryTests(unittest.TestCase):
    def setUp(self):
        folder=tempfile.TemporaryDirectory();self.addCleanup(folder.cleanup)
        self.con=connect(Path(folder.name)/'test.db');self.addCleanup(self.con.close)
        self.orgs=[Organization('child','AcmeCo','tech','US',('AcmeCo','Компания Альфа')),
                   Organization('parent','NorthGroup','tech','US',('NorthGroup','Компания Бета'))]
        upsert_organizations(self.con,self.orgs)

    def article(self,text,url='https://news.test/relationship',**extra):
        data=dict(url=url,title='Corporate news',summary=text,source_name='News',source_group='news.test',
                  published_at=utc_now(),kind='context',confidence=.4,rationale='Context',org_ids=['child','parent'])
        data.update(extra);return add_item(self.con,**data)

    def discover(self):
        from threatwatch.entity_graph import discover_relation_suggestions
        return discover_relation_suggestions(self.con,self.orgs)

    def test_explicit_subsidiary_sentence_is_cited_unverified_and_idempotent(self):
        self.article('AcmeCo, a wholly-owned subsidiary of NorthGroup, announced a new product.')
        self.assertEqual(self.discover()['inserted'],1)
        self.assertEqual(self.discover()['inserted'],0)
        row=organization_connections(self.con,'child')['documented'][0]
        self.assertEqual((row['source_org_id'],row['target_org_id'],row['relation_type']),('child','parent','parent'))
        self.assertEqual(row['review_status'],'unverified')
        self.assertIsNone(row['verified_at'])
        self.assertIn('wholly-owned subsidiary',row['evidence_excerpt'])
        self.con.execute("UPDATE organization_relations SET review_status='verified',verified_at=?",(utc_now(),))
        self.con.commit();self.discover()
        self.assertEqual(organization_connections(self.con,'child')['documented'][0]['review_status'],'verified')

    def test_russian_explicit_relationship_and_supplier(self):
        self.article('Компания Альфа — дочерняя компания Компания Бета.')
        self.article('AcmeCo is a supplier to NorthGroup.','https://news.test/supplier')
        self.assertEqual(self.discover()['inserted'],2)
        self.assertEqual({r['relation_type'] for r in organization_connections(self.con,'child')['documented']}, {'parent','supplier'})

    def test_completed_acquisition_keeps_direction(self):
        self.article('NorthGroup acquired AcmeCo.')
        self.assertEqual(self.discover()['inserted'],1)
        row=organization_connections(self.con,'child')['documented'][0]
        self.assertEqual((row['source_org_id'],row['target_org_id'],row['relation_type']),('parent','child','subsidiary'))

    def test_comention_negation_and_plans_do_not_become_relations(self):
        texts=['AcmeCo and NorthGroup reported earnings.',
               'AcmeCo is not a subsidiary of NorthGroup.',
               'AcmeCo is a former subsidiary of NorthGroup.',
               'NorthGroup plans to acquire AcmeCo.',
               'Rumors say NorthGroup acquired AcmeCo.',
               'AcmeCo is a supplier. NorthGroup is a customer.',
               'AcmeCoExtra is a subsidiary of NorthGroup.']
        for index,text in enumerate(texts):self.article(text,f'https://news.test/{index}')
        self.assertEqual(self.discover()['inserted'],0)
        self.assertEqual(organization_connections(self.con,'child')['documented'],[])

    def test_rejected_future_http_and_unmatched_items_not_used(self):
        self.article('AcmeCo is a subsidiary of NorthGroup.','https://news.test/demo',origin='synthetic')
        self.article('AcmeCo is a subsidiary of NorthGroup.',review_status='rejected')
        self.article('AcmeCo is a subsidiary of NorthGroup.','http://news.test/http')
        self.article('AcmeCo is a subsidiary of NorthGroup.','https://news.test/future',published_at='2999-01-01T00:00:00+00:00')
        self.article('AcmeCo is a subsidiary of NorthGroup.','https://news.test/single',org_ids=['child'])
        self.assertEqual(self.discover()['inserted'],0)

    def test_graph_shows_suggestions_and_respects_limit(self):
        from threatwatch.graph_render import relation_svg
        relations=[{'other_id':'suggested','other_name':'Proposed Parent','review_status':'unverified'},
                   {'other_id':'verified','other_name':'Verified Parent','review_status':'verified'}]
        graph=relation_svg('child','AcmeCo',relations,max_nodes=3,co_mentions=[{'id':'peer','name':'Mentioned Peer'}])
        self.assertIn('Proposed Parent',graph)
        self.assertIn('#d4ac79',graph)
        self.assertIn('stroke-dasharray="8 5"',graph)
        self.assertIn('stroke-dasharray="2 6"',graph)
        limited=relation_svg('child','AcmeCo',relations,max_nodes=1,co_mentions=[{'id':'peer','name':'Mentioned Peer'}])
        self.assertIn('Verified Parent',limited)
        self.assertNotIn('Proposed Parent',limited)
        self.assertNotIn('Mentioned Peer',limited)
        self.assertIn('Пока нет связей',relation_svg('child','AcmeCo',relations,max_nodes=0))


if __name__ == '__main__':
    unittest.main()
