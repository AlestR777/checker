"""Kaspersky Cybermap REFERENCE integration; no undocumented API or scraping.

Kaspersky's public map visualizes products' detections (OAS, ODS, etc.),
NOT breach attempts against a chosen organization. Site content is licensed;
use the site's official iframe and link to original pages. Analysts may import
small independently transcribed observations for their own noncommercial study,
with explicit date, source and units; such observations never alter org scores.
"""
from __future__ import annotations
import csv
import datetime as dt
import math
import re
from pathlib import Path
from urllib.parse import urlsplit
from .normalize import utc_now

STAT_URL="https://cybermap.kaspersky.com/ru/stats"
MAP_URL="https://cybermap.kaspersky.com/ru/"
NEWS_URL="https://cybermap.kaspersky.com/ru/buzz"
DATA_URL="https://cybermap.kaspersky.com/ru/subsystems"
WIDGET_URL="https://cybermap.kaspersky.com/ru/widget/dynamic/dark"
CATEGORIES=frozenset(('OAS','ODS','MAV','WAV','IDS','VUL','KAS','RMW'))
FIELDS=('observed_date','country','category','measurement','value','unit','source_url','analyst_note')


def import_observations(con, file: Path, *, today:dt.date|None=None) -> dict:
    """Import manually recorded public statistics with provenance.

    NOT an automatic scraper, feed downloader or telemetry service; do not
    modify Kaspersky materials or use percentages as organization attack rates.
    """
    today=today or dt.date.today()
    inserted=0; duplicate=0; errors=[]
    with file.open('r',encoding='utf-8-sig',newline='') as inp:
        reader=csv.DictReader(inp)
        if not reader.fieldnames or not set(FIELDS).issubset(reader.fieldnames):
            raise ValueError('Missing required Cybermap columns: '+', '.join(FIELDS))
        for line,r in enumerate(reader,start=2):
            try:
                date=dt.date.fromisoformat((r['observed_date'] or '').strip())
                if date>today or date.year<2000:
                    raise ValueError('Future or implausible observation date')
                metric=(r['category'] or '').strip().upper()
                if metric not in CATEGORIES:
                    raise ValueError('Unknown detection category')
                val=float(r['value'])
                if not math.isfinite(val) or val<0:
                    raise ValueError('Non-finite/negative value')
                unit=(r['unit'] or '').strip().lower()
                if unit not in {'%', 'count', 'per_second'}:
                    raise ValueError('Unit must be %, count, or per_second')
                if unit=='%' and val>100:
                    raise ValueError('Percent must not exceed 100')
                url=(r['source_url'] or '').strip()
                parsed=urlsplit(url)
                if parsed.scheme!='https' or parsed.hostname!='cybermap.kaspersky.com':
                    raise ValueError('Source must be a public Kaspersky Cybermap HTTPS page')
                country=(r['country'] or '').strip()
                measurement=(r['measurement'] or '').strip()
                if not country or not measurement or len(country)>90 or len(measurement)>140:
                    raise ValueError('Country and measurement are required')
                note=(r['analyst_note'] or '').strip()[:500]
                cur=con.execute('''INSERT OR IGNORE INTO cybermap_observations
                   (observed_date,country,category,measurement,value,unit,source_url,captured_at,analyst_note)
                   VALUES (?,?,?,?,?,?,?,?,?)''',(date.isoformat(),country,metric,measurement,val,
                                                      unit,url,utc_now(),note))
                inserted+=int(cur.rowcount>0)
                duplicate+=int(cur.rowcount==0)
            except (ValueError,TypeError) as exc:
                errors.append(f'line {line}: {exc}')
    con.commit()
    return {'inserted':inserted,'duplicates':duplicate,'errors':errors,
            'disclaimer':'Kaspersky endpoint detections are not breaches; imported figures are never used in organization scoring.'}


def recent_observations(con,limit=100):
    return [dict(x) for x in con.execute('''SELECT observed_date,country,category,measurement,value,unit,source_url,analyst_note
        FROM cybermap_observations ORDER BY observed_date DESC,id DESC LIMIT ?''',(max(1,min(limit,1000)),)).fetchall()]
