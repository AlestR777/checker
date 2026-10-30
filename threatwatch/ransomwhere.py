"""Public Ransomwhere.org victim-claim metadata, not evidence of a confirmed intrusion."""
from __future__ import annotations
import hashlib
from urllib.parse import urlencode
from .network import fetch_json
from .normalize import clean_markup,parse_date
from .feeds import Article

def parse_victims(payload,source_name='Ransomwhere',limit=100):
    if isinstance(payload,dict):
        payload=payload.get('victims') or payload.get('data') or []
    if not isinstance(payload,list):
        raise ValueError('Unexpected Ransomwhere API payload')
    items=[]
    for row in payload[:limit]:
        if not isinstance(row,dict):continue
        name=clean_markup(str(row.get('victim') or ''))[:140]
        if not name:continue
        group=clean_markup(str(row.get('group') or 'unknown'))[:80]
        country=clean_markup(str(row.get('country') or ''))[:50]
        sector=clean_markup(str(row.get('sector') or ''))[:80]
        date=parse_date(str(row.get('discovered') or row.get('date') or ''))
        rid=hashlib.sha256(f'{name}|{group}|{date}'.encode()).hexdigest()[:16]
        url='https://ransomwhere.org/api/victims?'+urlencode({'evidence_ref':rid})
        text=f'Unverified ransomware listing; group: {group}; country: {country}; sector: {sector}. Source: Ransomwhere public metadata (aggregated from ransomware.live).'
        items.append(Article(f'Ransomware claim: {name}',text,url,date,source_name,'ransomware-leak-monitors'))
    return items

def load_victims(url,name,limit):
    return parse_victims(fetch_json(url,max_bytes=3_000_000,timeout=24),name,limit)
