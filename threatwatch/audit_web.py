"""Human review queue for measuring entity extraction; review != ground truth automatically."""
from __future__ import annotations
import csv
import random
import tempfile
from pathlib import Path
from .entity_quality import _documents, FIELDS, evaluate_review_sample
from .normalize import utc_now

SCHEMA='''CREATE TABLE IF NOT EXISTS audit_web (
 url_key TEXT PRIMARY KEY,url TEXT NOT NULL,title TEXT NOT NULL,summary TEXT NOT NULL,
 published_at TEXT,source_name TEXT NOT NULL,predicted TEXT NOT NULL,
 expected TEXT NOT NULL DEFAULT '',reviewed_at TEXT,notes TEXT NOT NULL DEFAULT ''
);'''

def setup(con):
    con.execute(SCHEMA)
    con.commit()

def generate(con,size=80,seed=42):
    setup(con)
    existing=con.execute('SELECT count(*) FROM audit_web').fetchone()[0]
    if existing: return {'added':0,'existing':existing,'message':'Проверочная очередь уже есть'}
    docs=_documents(con)
    rng=random.Random(seed)
    with_predictions=[x for x in docs if x[1]]
    without=[x for x in docs if not x[1]]
    rng.shuffle(with_predictions);rng.shuffle(without)
    select=with_predictions[:size//2]+without[:size-size//2]
    if len(select)<size:
        chosen={row['url_key'] for row,_ in select}
        select.extend(x for x in with_predictions+without if x[0]['url_key'] not in chosen)
        select=select[:size]
    rng.shuffle(select)
    for row,names in select:
        con.execute('''INSERT OR IGNORE INTO audit_web
            (url_key,url,title,summary,published_at,source_name,predicted)
            VALUES(?,?,?,?,?,?,?)''',
            (row['url_key'],row['url'],row['title'],row['summary'],row['published_at'],row['source_name'],'|'.join(names)))
    con.commit()
    return {'added':len(select),'existing':0}

def save(con,url_key,expected,notes=''):
    setup(con)
    if not expected.strip():raise ValueError('Введи все организации через | или NONE')
    if len(expected)>1500 or len(notes)>800:raise ValueError('Слишком длинный текст')
    result=con.execute('UPDATE audit_web SET expected=?,notes=?,reviewed_at=? WHERE url_key=?',
                       (expected.strip(),notes.strip(),utc_now(),url_key))
    if not result.rowcount:raise ValueError('Статья не найдена в очереди')
    con.commit()

def progress(con):
    setup(con)
    count,reviewed=con.execute('SELECT count(*),count(reviewed_at) FROM audit_web').fetchone()
    return {'total':count,'reviewed':reviewed,'remaining':count-reviewed}

def pending(con):
    setup(con)
    return con.execute('SELECT * FROM audit_web WHERE reviewed_at IS NULL ORDER BY rowid LIMIT 1').fetchone()

def evaluate(con):
    setup(con)
    rows=con.execute('SELECT * FROM audit_web ORDER BY rowid').fetchall()
    if not rows:return {'status':'empty_queue'}
    with tempfile.NamedTemporaryFile('w',suffix='.csv',newline='',encoding='utf-8-sig',delete=False) as f:
        path=Path(f.name)
        writer=csv.DictWriter(f,fieldnames=FIELDS)
        writer.writeheader()
        for r in rows:
            writer.writerow({'url_key':r['url_key'],'url':r['url'],'published_at':r['published_at'],
                'source_name':r['source_name'],'title':r['title'],'summary':r['summary'],
                'predicted_organizations':r['predicted'],
                'reviewed':'yes' if r['reviewed_at'] else '',
                'expected_organizations':r['expected'],'reviewer_notes':r['notes']})
    try:return evaluate_review_sample(path)
    finally:path.unlink(missing_ok=True)
