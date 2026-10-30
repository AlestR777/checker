"""Public Ransomfeed metadata adapter (claimed victim names only).

Official API: https://api.ransomfeed.it/docs/html. Each record is a claim, NOT proof.
"""
from __future__ import annotations
from urllib.parse import quote
from .normalize import parse_date, clean_markup
from .network import fetch_json


def parse_claims(payload, source_name: str, max_items: int = 100):
    from .feeds import Article
    if isinstance(payload, dict):
        rows = payload.get('data',payload.get('results',payload.get('items',[])))
    else:
        rows = payload
    if not isinstance(rows,list):
        raise ValueError('Unexpected Ransomfeed API payload: expected an array')
    articles = []
    for row in rows[:max_items]:
        if not isinstance(row,dict):
            continue
        name = clean_markup(str(row.get('victim') or row.get('victim_name') or ''))
        if not name:
            continue
        gang = clean_markup(str(row.get('gang') or row.get('group') or 'Unknown'))
        date = parse_date(str(row.get('date') or row.get('discovered') or row.get('published') or ''))
        # The API record identifies its page. Do not link to onion, access listings, or stolen files.
        rid = str(row.get('id') or '')
        # Officially documented searchable API endpoint; query marker records evidence identity.
        search_term = quote(name[:120], safe='')
        identifier = quote((rid or (gang + '-' + (date or 'unknown')))[:120], safe='')
        url = f'https://api.ransomfeed.it/search/{search_term}?evidence_ref={identifier}'
        country = clean_markup(str(row.get('country') or ''))
        sector = clean_markup(str(row.get('work_sector') or ''))
        summary = f'Unverified ransomware listing; group: {gang}; country: {country}; sector: {sector}. Source: Ransomfeed public metadata.'
        articles.append(Article(title=f'Ransomware claim: {name}',summary=summary,url=url,
                                published_at=date,source_name=source_name,source_group='ransomware-leak-monitors'))
    return articles


def load_claims(url: str, source_name: str, max_items: int = 100):
    return parse_claims(fetch_json(url, max_bytes=4_000_000), source_name, max_items)
