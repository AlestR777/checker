"""Sector-level news context, separate from direct attack evidence.

Counts are matches to broad sector vocabulary in public article headlines and
snippets. They measure coverage by this partial collection, not attack rates.
They must never be used as evidence that a named organization is vulnerable.
"""
from __future__ import annotations
import datetime as dt
import re
from .normalize import plain, UTC

SECTORS = {
 'public_administration': ['ministere','mairie','municipalit','collectivite','prefecture','administration publique','government agency','public sector','service public','mairies','government website'],
 'retail': ['supermarche','retail','grande distribution','commercant','commerce de detail','magasin','supermarket'],
 'energy': ['electricite','energie','energy company','electrical grid','power utility','nucleaire'],
 'telecom': ['telecom','operateur mobile','mobile operator','fournisseur internet','telecommunications'],
 'manufacturing': ['usine','industrie','industrial','manufactur','fabricant','production plant'],
 'politics': ['parti politique','political party','parti francais','elections','campagne electorale','election'],
 'transport': ['transport','logistique','ferroviaire','autobus','ferry','compagnie aerienne'],
 'maritime': ['maritime','portuaire','navire','shipping','shipyard','port de commerce'],
}


def sector_snapshot(con, sector: str, days: int=28, *, now: dt.datetime|None=None) -> dict:
    """Use distinct URL keys and fixed bins; no assumption of independence."""
    now=now or dt.datetime.now(UTC)
    cutoff=(now-dt.timedelta(days=days)).isoformat(timespec='seconds')
    prior_cutoff=(now-dt.timedelta(days=days*2)).isoformat(timespec='seconds')
    vocabulary=SECTORS.get(sector,[])
    if not vocabulary:
        return {'sector':sector,'status':'not_supported','current_articles':0,'prior_articles':0,'sources':0}
    rows=con.execute('''SELECT url_key,title,summary,published_at,source_group FROM discovery
        WHERE published_at BETWEEN ? AND ?
        UNION SELECT url_key,title,summary,published_at,source_group FROM items
        WHERE published_at BETWEEN ? AND ?''',(prior_cutoff,now.isoformat(),prior_cutoff,now.isoformat())).fetchall()
    matches={}
    for r in rows:
        text=plain(f"{r['title']} {r['summary']}")
        if any(re.search(r'(?<!\w)'+re.escape(plain(token))+r'(?!\w)',text) for token in vocabulary):
            matches[r['url_key']]=r
    current=[r for r in matches.values() if r['published_at']>=cutoff]
    prior=[r for r in matches.values() if r['published_at']<cutoff]
    return {'sector':sector,'status':'weak_article_context_not_event_rate',
            'current_articles':len(current),'prior_articles':len(prior),
            'sources':len({r['source_group'] for r in current if r['source_group']}),
            'days_per_window':days,
            'note':'Keyword-matched coverage, not verified incidents, target interest or breach likelihood.'}
