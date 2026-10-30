"""Read-only adapters to public *metadata* about ransomware allegations.

Sources are aggregators of criminals' claims, not independent validations.
No attachments, negotiation chats, credentials, leak files or .onion retrieval.
"""
from __future__ import annotations
import hashlib
from urllib.parse import quote, urlsplit
import socket
import time
from urllib.error import URLError
from .network import fetch_json
from .normalize import parse_date, clean_markup

SHARED_ORIGIN = 'ransomware-leak-monitors'  # multiple trackers may republish ONE original claim


def _rows(data):
    if isinstance(data, list):
        return data
    if isinstance(data,dict):
        for key in ('data','posts','victims','results','items','recentvictims'):
            v = data.get(key)
            if isinstance(v,list):
                return v
    raise ValueError('Unknown claim-feed JSON shape; verify upstream API documentation')


def _record(victim, group, discovered, provider, source_api, direct_link=''):
    from .feeds import Article
    victim = clean_markup(str(victim or ''))[:180]
    if not victim:
        return None
    group = clean_markup(str(group or 'unspecified'))[:90]
    when = parse_date(str(discovered or ''))
    # A public API link, not a listing on a criminal website.
    if direct_link and direct_link.startswith('/') and provider == 'RansomLook':
        uri = 'https://www.ransomlook.io' + direct_link
    else:
        # Retrieval link for the exact query window. The hash is metadata for dedup only;
        # source API endpoint does not promise permanent item-level permalinks.
        ref = hashlib.sha256(f'{group}|{victim}|{when}'.encode()).hexdigest()[:20]
        uri = source_api + ('&' if '?' in source_api else '?') + 'ref=' + ref
    if urlsplit(uri).scheme!='https':
        return None
    return Article(f'Ransomware claim: {victim}',
        f'Unverified group listing; actor: {group}; monitored by {provider}. This is not confirmed compromise.',
        uri,when,provider,SHARED_ORIGIN)


def parse_ransomlook(payload, source_name='RansomLook',limit=100):
    articles=[]
    for row in _rows(payload)[:limit]:
        if not isinstance(row,dict):
            continue
        article=_record(row.get('post_title'),row.get('group_name'),
               row.get('discovered'),source_name,'https://www.ransomlook.io/api/posts?days=7',row.get('link',''))
        if article:
            articles.append(article)
    return articles


def parse_ransomware_live(payload, source_name='Ransomware.live',limit=100):
    articles=[]
    for row in _rows(payload)[:limit]:
        if not isinstance(row,dict):
            continue
        article=_record(row.get('victim') or row.get('post_title') or row.get('name'),
               row.get('group_name') or row.get('group'),
               row.get('discovered') or row.get('date'),
               source_name,'https://api.ransomware.live/v2/recentvictims')
        if article:
            articles.append(article)
    return articles


def load_claim_source(kind,url,name,limit,timeout=35):
    # One bounded retry for transient timeouts. Persistent errors remain visible in source health.
    try:
        payload=fetch_json(url,max_bytes=5_000_000,timeout=timeout)
    except (TimeoutError, socket.timeout, URLError) as exc:
        if 'timed out' not in str(exc).lower() and not isinstance(exc,(TimeoutError,socket.timeout)):
            raise
        time.sleep(1)
        payload=fetch_json(url,max_bytes=5_000_000,timeout=timeout)
    if kind=='ransomlook_api':
        return parse_ransomlook(payload,name,limit)
    if kind=='ransomware_live_api':
        return parse_ransomware_live(payload,name,limit)
    raise ValueError(f'Unknown source adapter {kind}')
