"""Public GDELT DOC 2.0 search adapter (article metadata only).

Editorial mentions and publishing location are NOT evidence that a victim belongs
in that country. Publication first-seen time is NOT the date of a breach.
"""
from __future__ import annotations
from urllib.parse import urlencode
from .network import fetch_json
from .normalize import clean_markup, parse_date, source_domain
from .feeds import Article

API='https://api.gdeltproject.org/api/v2/doc/doc'


def query_url(query:str,limit:int=75,timespan:str='7d')->str:
    if not (4<=len(query)<=500): raise ValueError('GDELT search query must be 4–500 characters')
    if timespan not in {'1d','3d','7d','14d','1m'}:
        raise ValueError('Unsupported GDELT timespan')
    args={'query':query,'mode':'artlist','format':'json',
          'maxrecords':max(1,min(250,int(limit))),'timespan':timespan,'sort':'datedesc'}
    return API+'?'+urlencode(args)


def parse_articles(payload,source_name='GDELT DOC',max_items:int=75)->list[Article]:
    if not isinstance(payload,dict) or not isinstance(payload.get('articles'),list):
        raise ValueError('GDELT returned unexpected JSON; check quota and API status')
    articles=[]
    for row in payload['articles'][:max_items]:
        if not isinstance(row,dict):continue
        url=str(row.get('url') or '')
        if not url.startswith('https://') and not url.startswith('http://'):continue
        title=clean_markup(str(row.get('title') or ''))
        if not title:continue
        raw_date=str(row.get('seendate') or '')
        # GDELT date format is often YYYYMMDDTHHMMSSZ
        if len(raw_date)>=16 and raw_date[8]=='T' and raw_date.endswith('Z'):
            raw_date=f'{raw_date[:4]}-{raw_date[4:6]}-{raw_date[6:8]}T{raw_date[9:11]}:{raw_date[11:13]}:{raw_date[13:15]}Z'
        published=parse_date(raw_date)
        desc=('GDELT indexed editorial article. Country of publication: '
              +str(row.get('sourcecountry') or 'unknown')
              +'. News publication does not verify an incident or locate the affected organization.')
        articles.append(Article(title=title,summary=desc,url=url,
                                published_at=published,source_name=source_name,
                                source_group=source_domain(url)))
    return articles


def load_articles(src:dict)->list[Article]:
    url=query_url(src['query'],src.get('max_items',75),src.get('timespan','7d'))
    return parse_articles(fetch_json(url,timeout=int(src.get('timeout',25)),max_bytes=2_500_000),
                          src.get('name','GDELT DOC'),int(src.get('max_items',75)))
