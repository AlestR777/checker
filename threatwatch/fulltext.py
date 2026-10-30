"""Optional conservative public EDITORIAL article text enrichment.

No requests to victim infrastructure, private data, dynamic browser rendering,
file attachments, credentials, or arbitrary domains. Respect publisher policies.
"""
from __future__ import annotations
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit
from .network import fetch_bytes
from .normalize import clean_markup,utc_now

EDITORIAL_HOSTS = frozenset({
    'www.bleepingcomputer.com', 'bleepingcomputer.com',
    'therecord.media', 'www.therecord.media',
    'www.zataz.com', 'zataz.com',
    'www.01net.com', '01net.com',
    'www.lemonde.fr', 'lemonde.fr',
    'www.france24.com', 'france24.com',
})


class ArticleTextParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.skip=0
        self.inside=0
        self.all=[]
        self.article=[]
    def handle_starttag(self,tag,attrs):
        if tag in {'script','style','nav','footer','header','noscript','form','svg'}:
            self.skip+=1
        if tag=='article':
            self.inside+=1
        if tag in {'p','h1','h2','h3','li','br'}:
            self.all.append(' ')
            if self.inside:self.article.append(' ')
    def handle_endtag(self,tag):
        if tag in {'script','style','nav','footer','header','noscript','form','svg'} and self.skip:
            self.skip-=1
        if tag=='article' and self.inside:
            self.inside-=1
    def handle_data(self,text):
        if self.skip:return
        self.all.append(text)
        if self.inside:self.article.append(text)


def parse_article_html(data: bytes) -> str:
    p=ArticleTextParser();p.feed(data.decode('utf-8',errors='replace'))
    text=clean_markup(' '.join(p.article))
    if len(text)<250:text=clean_markup(' '.join(p.all))
    return text[:12000]


def enrich_pages(con, *, limit=10, delay=2.0, force=False):
    ids=con.execute("""SELECT i.id,i.url FROM items i
     LEFT JOIN page_texts t ON t.item_id=i.id
     WHERE (?=1 OR t.item_id IS NULL) ORDER BY i.published_at DESC LIMIT 1500""",
     (int(force),)).fetchall()
    result={'checked':0,'saved':0,'failed':0,'skipped_unapproved_hosts':0,'errors':[]}
    for row in ids:
        if result['checked']>=limit:
            break
        url=row['url'];parts=urlsplit(url)
        if parts.scheme!='https' or parts.hostname not in EDITORIAL_HOSTS or parts.port not in (None,443):
            result['skipped_unapproved_hosts']+=1
            continue
        if result['checked'] and delay:time.sleep(delay)
        result['checked']+=1
        try:
            payload=fetch_bytes(url,timeout=18,max_bytes=600_000,accept='text/html',allowed_hosts=EDITORIAL_HOSTS)
            text=parse_article_html(payload)
            if len(text)<200:
                raise ValueError('Article text too short to reliably extract')
            con.execute('''INSERT OR REPLACE INTO page_texts(item_id,extracted_text,status,fetched_at,error)
                VALUES (?,?,?,?,?)''',(row['id'],text,'ok',utc_now(),''))
            result['saved']+=1
        except Exception as exc:
            result['failed']+=1
            result['errors'].append(f"{url[:85]}: {str(exc)[:100]}")
            con.execute('''INSERT OR REPLACE INTO page_texts(item_id,extracted_text,status,fetched_at,error)
                VALUES (?,?,?,?,?)''',(row['id'],'','error',utc_now(),str(exc)[:350]))
        con.commit()
    return result


def analyze_saved_pages(con, *, model_path=None, ai=False, threshold=.80, limit=30):
    """Classify previously approved public editorial text; manual reviews are immutable.

    Does not train on these predictions and never upgrades an allegation to a
    verified compromise. Only replaces a text *category* with an audit note.
    """
    from .ai import AIClassifier
    from .text_model import predict
    from .config import ROOT
    from .scoring import recompute_all
    from .config import load_organizations
    if not model_path:
        model_path=ROOT/'models'/'text_model.joblib'
    classifier=AIClassifier() if ai else None
    rows=con.execute('''SELECT i.id,i.title,i.source_group,i.kind,t.extracted_text
      FROM page_texts t JOIN items i ON i.id=t.item_id
      WHERE t.status='ok' AND i.review_status='unreviewed'
        AND i.source_group!='ransomware-leak-monitors' AND i.origin!='synthetic'
      ORDER BY t.fetched_at DESC LIMIT ?''',(max(1,min(limit,500)),)).fetchall()
    stats={'processed':0,'updated':0,'kept':0,'results':[]}
    for row in rows:
        text=row['extracted_text']
        if not text:
            continue
        stats['processed']+=1
        pred=None
        if classifier and classifier.enabled:
            org_ids=[m['org_id'] for m in con.execute('SELECT org_id FROM mentions WHERE item_id=?',(row['id'],))]
            resp=classifier.classify(row['title'],text[:1600],org_ids)
            if resp:
                pred={'label':resp[0],'confidence':resp[1],'source':'openai'}
        elif not ai:
            result=predict(model_path,text)
            if result.get('status')=='predicted_text_label_not_incident_probability':
                pred={'label':result['label'],'confidence':result['confidence'],'source':'local_text_model'}
        if pred and pred['confidence']>=threshold:
            con.execute('UPDATE items SET kind=?,confidence=?,rationale=?,ai_used=? WHERE id=?',
              (pred['label'],min(.80,pred['confidence']),
               f'Category inferred from public article text by {pred["source"]}; not verified',
               int(pred['source']=='openai'),row['id']))
            stats['updated']+=1
            stats['results'].append({'item_id':row['id'],'label':pred['label'],'confidence':round(pred['confidence'],3)})
        else:
            stats['kept']+=1
    con.commit()
    if stats['updated']:
        recompute_all(con,[o.id for o in load_organizations()])
    return stats
