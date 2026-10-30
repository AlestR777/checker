"""Global catalog, bounded targeted collection and locale regressions."""
import unittest
from urllib.parse import parse_qs, urlsplit

from threatwatch.config import Organization, load_organizations, load_sources
from threatwatch.feeds import google_rss, source_definitions


class GlobalCoverageTests(unittest.TestCase):
    def test_catalog_keeps_legacy_and_adds_global_domiciles(self):
        organizations = load_organizations()
        ids = {org.id for org in organizations}
        self.assertTrue({'edf', 'carrefour', 'ville-de-paris', 'les-republicains'} <= ids)
        self.assertTrue({'microsoft', 'sberbank', 'toyota', 'tencent', 'petrobras', 'telstra'} <= ids)
        self.assertTrue({'US', 'RU', 'JP', 'CN', 'BR', 'AU', 'ZA', 'IN', 'DE'} <=
                        {org.country for org in organizations})
        self.assertEqual(len(organizations), len(ids))
        for org in organizations:
            self.assertTrue(org.aliases)
            self.assertEqual(len(org.country), 2)

    def test_optional_language_sources_do_not_expand_default_collection(self):
        active = load_sources()
        self.assertLessEqual(len(source_definitions(active, load_organizations())), 8)
        optional = [source for source in load_sources(include_disabled=True)
                    if source['id'].startswith('google-incidents-')]
        self.assertTrue({'ru', 'ja', 'ko', 'zh', 'pt'} <= {s['locale'] for s in optional})
        self.assertFalse(any(source['enabled'] for source in optional))

    def test_targeted_source_honors_locale_and_explicit_subset(self):
        orgs = [Organization('one', 'Global One', 'technology', 'US', ('Global One',)),
                Organization('two', '会社 Example', 'technology', 'JP', ('会社 Example',))]
        source = dict(id='targeted', name='Targeted', type='google_org_search',
                      locale='ja', query_suffix='サイバー攻撃', org_ids=['two'])
        jobs = source_definitions([source], orgs)
        self.assertEqual(len(jobs), 1)
        params = parse_qs(urlsplit(jobs[0][1]).query)
        self.assertEqual(params['hl'], ['ja'])
        self.assertEqual(params['gl'], ['JP'])
        self.assertIn('会社 Example', params['q'][0])
        self.assertNotIn('Global One', params['q'][0])
        source['org_ids'] = []
        self.assertEqual(source_definitions([source], orgs), [])

    def test_shared_rss_endpoint_fetched_once_with_larger_limit(self):
        sources = [dict(name='legacy', type='rss', url='https://example.org/feed/', max_items=20),
                   dict(name='current', type='rss', url='https://example.org/feed', max_items=50)]
        self.assertEqual(source_definitions(sources, []), [('legacy', 'https://example.org/feed/', 50)])

    def test_new_google_language_region_pairs(self):
        for locale, language, country in [('ru', 'ru', 'RU'), ('pt', 'pt-BR', 'BR'),
                                          ('ja', 'ja', 'JP'), ('ko', 'ko', 'KR'),
                                          ('zh', 'zh-TW', 'TW')]:
            with self.subTest(locale=locale):
                params = parse_qs(urlsplit(google_rss('incident', locale)).query)
                self.assertEqual(params['hl'], [language])
                self.assertEqual(params['ceid'], [country + ':' + language])


if __name__ == '__main__':
    unittest.main()
