"""Descriptive publishing statistics, explicitly NOT breach counts or probabilities."""
from __future__ import annotations


def aggregate(con,limit=25):
    base='''WITH evidence(country,sector,url_key) AS (
        SELECT c.country,c.sector,e.url_key FROM candidate_evidence e
        JOIN entity_candidates c ON e.candidate_id=c.id
        UNION ALL
        SELECT o.country,o.sector,i.url_key FROM items i
        JOIN mentions m ON i.id=m.item_id
        JOIN organizations o ON m.org_id=o.id
    )'''
    countries=con.execute(base+'''SELECT COALESCE(NULLIF(country,''),'Unknown') AS label,
         COUNT(DISTINCT url_key) AS publications FROM evidence
         GROUP BY label ORDER BY publications DESC,label LIMIT ?''',(limit,)).fetchall()
    sectors=con.execute(base+'''SELECT COALESCE(NULLIF(sector,''),'Unknown') AS label,
         COUNT(DISTINCT url_key) AS publications FROM evidence
         GROUP BY label ORDER BY publications DESC,label LIMIT ?''',(limit,)).fetchall()
    daily=con.execute('''SELECT substr(published_at,1,10) AS day, COUNT(DISTINCT url_key) AS publications
         FROM (SELECT url_key,published_at FROM items UNION ALL SELECT url_key,published_at FROM discovery)
         WHERE published_at IS NOT NULL GROUP BY day ORDER BY day DESC LIMIT 30''').fetchall()
    return {'countries':[dict(r) for r in countries],
            'sectors':[dict(r) for r in sectors],
            'daily':list(reversed([dict(r) for r in daily])),
            'meaning':'These counts are article-evidence records, not successful attacks, distinct victims or probabilities.'}
