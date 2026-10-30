"""Incident-first entity discovery and provenance-aware organization relations.

No discovery output is a validated victim, corporate relationship or probability.
Candidates require analyst approval before promotion to the organization catalog.
"""
from __future__ import annotations
import csv
import hashlib
import json
import re
import sqlite3
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit
from .normalize import utc_now, plain
from .config import Organization

GRAPH_SCHEMA = """
CREATE TABLE IF NOT EXISTS entity_candidates (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 name_key TEXT NOT NULL UNIQUE,
 name TEXT NOT NULL,
 country TEXT NOT NULL DEFAULT '',
 sector TEXT NOT NULL DEFAULT '',
 status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','approved','rejected')),
 first_seen TEXT NOT NULL,
 last_seen TEXT NOT NULL,
 detection_method TEXT NOT NULL,
 reviewed_org_id TEXT NOT NULL DEFAULT '',
 reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS candidate_evidence (
 candidate_id INTEGER NOT NULL REFERENCES entity_candidates(id) ON DELETE CASCADE,
 url_key TEXT NOT NULL,
 url TEXT NOT NULL,
 published_at TEXT,
 source_name TEXT NOT NULL,
 source_group TEXT NOT NULL,
 kind TEXT NOT NULL,
 PRIMARY KEY(candidate_id,url_key)
);
CREATE INDEX IF NOT EXISTS idx_candidate_status ON entity_candidates(status,country,sector);
CREATE TABLE IF NOT EXISTS organization_relations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_org_id TEXT NOT NULL REFERENCES organizations(id),
 target_org_id TEXT NOT NULL REFERENCES organizations(id),
 relation_type TEXT NOT NULL,
 evidence_url TEXT NOT NULL,
 review_status TEXT NOT NULL CHECK(review_status IN ('verified','unverified')),
 recorded_at TEXT NOT NULL,
 UNIQUE(source_org_id,target_org_id,relation_type,evidence_url)
);
CREATE TABLE IF NOT EXISTS pending_relation_suggestions (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source_org_id TEXT NOT NULL REFERENCES organizations(id),
 target_candidate_id INTEGER NOT NULL REFERENCES entity_candidates(id),
 relation_type TEXT NOT NULL,
 evidence_url TEXT NOT NULL,
 source_qid TEXT NOT NULL DEFAULT '',
 target_qid TEXT NOT NULL DEFAULT '',
 recorded_at TEXT NOT NULL,
 UNIQUE(source_org_id,target_candidate_id,relation_type,evidence_url)
);
CREATE TABLE IF NOT EXISTS relation_suggestion_evidence (
 relation_id INTEGER NOT NULL REFERENCES organization_relations(id) ON DELETE CASCADE,
 item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 excerpt TEXT NOT NULL,
 detection_method TEXT NOT NULL,
 PRIMARY KEY(relation_id,item_id)
);
CREATE INDEX IF NOT EXISTS idx_relation_source ON organization_relations(source_org_id);
CREATE INDEX IF NOT EXISTS idx_relation_target ON organization_relations(target_org_id);
"""


def ensure_schema(con: sqlite3.Connection) -> None:
    con.executescript(GRAPH_SCHEMA)
    cols={r[1] for r in con.execute('PRAGMA table_info(entity_candidates)')}
    edge_cols={r[1] for r in con.execute('PRAGMA table_info(organization_relations)')}
    if 'verified_at' not in edge_cols:
        con.execute('ALTER TABLE organization_relations ADD COLUMN verified_at TEXT')
        # Legacy review confirmation time is unknown; do not backdate.
        con.execute("UPDATE organization_relations SET verified_at=? WHERE review_status='verified' AND verified_at IS NULL",(utc_now(),))
    if 'reviewed_at' not in cols:
        con.execute('ALTER TABLE entity_candidates ADD COLUMN reviewed_at TEXT')
        # An old approval is first observable at migration time. Never
        # pretend to know the original historic approval date.
        con.execute("UPDATE entity_candidates SET reviewed_at=? WHERE status='approved' AND reviewed_at IS NULL",(utc_now(),))


def entity_key(name: str) -> str:
    cleaned=plain(name)
    return re.sub(r"[\W_]+", "-", cleaned, flags=re.UNICODE).strip("-")[:180]


def eligible_name(name: str) -> bool:
    n=' '.join(str(name).split()).strip(' .,:;')
    minimum=2 if re.search(r'[\u3400-\u9fff\u3040-\u30ff]',n) else 3
    if not (minimum<=len(n)<=140): return False
    if not any(c.isalpha() for c in n): return False
    if re.fullmatch(r'(?:France|Italy|Germany|Cyberattack|Ransomware|Unknown|Hackers|Victim|Data Leak|Россия|Кибератака|Хакеры|Неизвестно)',n,re.I): return False
    if n.lower().startswith(('http://','https://')): return False
    if sum(c.isdigit() for c in n)>len(n)//2: return False
    return bool(entity_key(n))


def extract_explicit_victim(title: str) -> str | None:
    """Only parse victim-identifying, *structured* tracker titles; no fuzzy NER guesses."""
    match=re.fullmatch(r'Ransomware claim:\s*(.+)',title.strip(),re.I)
    if not match: return None
    name=match.group(1).strip()
    return name if eligible_name(name) else None


COUNTRY_CODES={
    'france':'FR','italy':'IT','italia':'IT','germany':'DE','deutschland':'DE',
    'spain':'ES','españa':'ES','united kingdom':'GB','uk':'GB',
    'united states':'US','usa':'US','canada':'CA','netherlands':'NL',
    'poland':'PL','belgium':'BE','switzerland':'CH','australia':'AU',
    'russia':'RU','россия':'RU','российская федерация':'RU','china':'CN','китай':'CN',
    'india':'IN','brazil':'BR','japan':'JP','south korea':'KR','ukraine':'UA','украина':'UA',
}


HEADLINE_PATTERNS=(
    re.compile(r"^(.{3,100}?)\s+(?:подверг\w*|пострадал\w* от)\s+(?:масштабн\w* )?(?:кибератак\w*|атак\w* хакер\w*|взлом\w*)\b", re.I),
    re.compile(r"^(.{3,100}?)\s+(?:подтверд\w*|сообщил\w* о)\s+(?:утечк\w* данных|кибератак\w*|взлом\w*)\b", re.I),
    re.compile(r"^(.{3,100}?)\s+(?:hit by|hit with|suffers|reports|confirms)\s+(?:a |an )?(?:ransomware|cyberattack|cyber attack|data breach|DDoS attack)\b",re.I),
    re.compile(r"^(.{3,100}?)\s+(?:victime d[’']une? cyberattaque|ciblée? par une cyberattaque|victime d[’']un piratage)\b",re.I),
)

def extract_headline_subject(title:str)->str|None:
    """Conservative title grammar; all results must be reviewed as suggestions."""
    for pattern in HEADLINE_PATTERNS:
        hit=pattern.search(title.strip())
        if hit:
            name=hit.group(1).strip(' :—-„“"')
            # Drop journalistic attribution phrases that are not part of a legal name.
            name=re.sub(r'\s+(?:says|reports|claims)\s+(?:it|they)\s+(?:was|were|has been)$','',name,flags=re.I)
            if eligible_name(name) and len(name.split())<=10:
                return name
    return None


def explicit_metadata(summary: str) -> tuple[str,str]:
    """Read structured tracker fields, never infer the victim country from news domain."""
    country,sector='',''
    m=re.search(r'(?:^|;)\s*country:\s*([^;.]+)',summary,re.I)
    if m:
        raw=m.group(1).strip()[:70]
        country=COUNTRY_CODES.get(raw.casefold(),raw.upper() if len(raw)==2 else raw)
    m=re.search(r'(?:^|;)\s*sector:\s*([^;.]+)',summary,re.I)
    if m: sector=m.group(1).strip()[:110]
    return country,sector


def _candidate(con,name,country,sector,method,*,url,url_key,published_at,source_name,source_group,kind) -> bool:
    if not eligible_name(name): return False
    name=' '.join(name.split()).strip()
    key=entity_key(name)
    now=utc_now()
    con.execute('''INSERT INTO entity_candidates(name_key,name,country,sector,status,first_seen,last_seen,detection_method)
       VALUES(?,?,?,?,'pending',?,?,?) ON CONFLICT(name_key) DO UPDATE SET
       last_seen=excluded.last_seen,
       country=CASE WHEN entity_candidates.country='' THEN excluded.country ELSE entity_candidates.country END,
       sector=CASE WHEN entity_candidates.sector='' THEN excluded.sector ELSE entity_candidates.sector END''',
       (key,name,country,sector,now,now,method))
    cid=con.execute('SELECT id FROM entity_candidates WHERE name_key=?',(key,)).fetchone()[0]
    cur=con.execute('''INSERT OR IGNORE INTO candidate_evidence
       (candidate_id,url_key,url,published_at,source_name,source_group,kind)
       VALUES (?,?,?,?,?,?,?)''',(cid,url_key,url,published_at,source_name,source_group,kind))
    return bool(cur.rowcount)


def discover_from_ledger(con: sqlite3.Connection, limit: int=5000, include_ai: bool=False) -> dict:
    """Extract explicit tracker-listed names into pending review queue.

    AI suggestions are optional and require explicit opt-in; they never become approved
    organizations or count as independently verified attacks.
    """
    ensure_schema(con)
    # Items include known entities, discovery contains unmatched articles.
    rows=con.execute('''SELECT url_key,url,title,summary,source_name,source_group,published_at,kind,candidate_name
      FROM discovery UNION ALL SELECT url_key,url,title,summary,source_name,source_group,published_at,kind,'' AS candidate_name FROM items
      ORDER BY published_at DESC LIMIT ?''',(max(1,min(limit,50000)),)).fetchall()
    results={'examined':len(rows),'new_evidence':0,'candidate_count':0,'ai_suggestions_used':0}
    # Avoid duplicating already tracked names and known aliases as candidates.
    from .config import load_organizations
    known={entity_key(x['name']) for x in con.execute('SELECT name FROM organizations')}
    try:
        known.update(entity_key(alias) for org in load_organizations() for alias in org.aliases)
    except (OSError,ValueError):
        pass
    for row in rows:
        name=extract_explicit_victim(row['title'])
        method='structured_tracker_title' if name else 'headline_subject_heuristic'
        if not name and row['candidate_name'] and eligible_name(row['candidate_name']):
            name=row['candidate_name'];method='label_from_publication'
        if not name: name=extract_headline_subject(row['title'])
        if not name or entity_key(name) in known: continue
        country,sector=explicit_metadata(row['summary'])
        results['new_evidence']+=int(_candidate(con,name,country,sector,method,
             url=row['url'],url_key=row['url_key'],published_at=row['published_at'],
             source_name=row['source_name'],source_group=row['source_group'],kind=row['kind']))
    if include_ai:
        suggestions=con.execute('''SELECT d.*,s.organization_names_json FROM discovery d
           JOIN discovery_suggestions s ON d.url_key=s.url_key ORDER BY d.published_at DESC LIMIT ?''',
           (max(1,min(limit,5000)),)).fetchall()
        for row in suggestions:
            try: names=json.loads(row['organization_names_json'])
            except (ValueError,TypeError): continue
            if not isinstance(names,list): continue
            for name in names[:8]:
                if not isinstance(name,str): continue
                if _candidate(con,name,'','','unverified_local_ai_suggestion',url=row['url'],
                    url_key=row['url_key'],published_at=row['published_at'],
                    source_name=row['source_name'],source_group=row['source_group'],kind=row['kind']):
                    results['ai_suggestions_used']+=1
    con.commit()
    results['candidate_count']=con.execute("SELECT count(*) FROM entity_candidates WHERE status='pending'").fetchone()[0]
    return results


def list_candidates(con, *, country: str='',sector: str='',status: str='pending',limit: int=200) -> list[dict]:
    conditions=['1=1']; params=[]
    if country: conditions.append('c.country=?');params.append(country)
    if sector: conditions.append('c.sector=?');params.append(sector)
    if status: conditions.append('c.status=?');params.append(status)
    rows=con.execute(f'''SELECT c.*,COUNT(e.url_key) AS publications,
         COUNT(DISTINCT e.source_group) AS source_groups,
         MIN(e.published_at) AS earliest_publication
         FROM entity_candidates c LEFT JOIN candidate_evidence e ON e.candidate_id=c.id
         WHERE {' AND '.join(conditions)} GROUP BY c.id ORDER BY c.last_seen DESC LIMIT ?''',
         [*params,max(1,min(limit,1000))]).fetchall()
    return [dict(r) for r in rows]


def approve_candidate(con: sqlite3.Connection, candidate_id: int, *, country: str, sector: str) -> dict:
    """Promotion is an explicit analyst action; never infer country/sector."""
    from .normalize import matching_organizations
    from .store import add_item
    if not re.fullmatch(r'[A-Z]{2}',country.upper()):
        raise ValueError('Country must be a two-letter ISO 3166-1 code, e.g. FR or IT')
    sector=sector.strip()
    if not (2<=len(sector)<=100): raise ValueError('Sector is required for approving a candidate')
    row=con.execute('SELECT * FROM entity_candidates WHERE id=?',(candidate_id,)).fetchone()
    if not row: raise ValueError('Unknown candidate')
    if row['status']=='rejected': raise ValueError('Candidate was rejected')
    # Organization IDs remain URL-safe even when display names are non-Latin.
    slug=re.sub(r'[^a-z0-9-]', '', entity_key(row['name']))[:65].strip('-') or 'entity'
    oid='discovered-'+slug+'-'+hashlib.sha256(row['name_key'].encode()).hexdigest()[:8]
    con.execute('INSERT OR IGNORE INTO organizations(id,name,sector,country,notes) VALUES (?,?,?,?,?)',
                (oid,row['name'],sector,country.upper(),'Analyst-approved monitoring entity from incident-first catalog; not a confirmed victim.'))
    con.execute("UPDATE entity_candidates SET status='approved',reviewed_org_id=?,reviewed_at=COALESCE(reviewed_at,?) WHERE id=?",(oid,utc_now(),candidate_id))
    ev=con.execute('SELECT * FROM candidate_evidence WHERE candidate_id=?',(candidate_id,)).fetchall()
    from .store import add_item
    linked=0
    for e in ev:
        existing=con.execute('SELECT * FROM items WHERE url_key=?',(e['url_key'],)).fetchone()
        if existing:
            if con.execute('SELECT 1 FROM mentions WHERE item_id=? AND org_id=?',(existing['id'],oid)).fetchone():
                continue
            add_item(con,url=existing['url'],title=existing['title'],summary=existing['summary'],
                source_name=existing['source_name'],published_at=existing['published_at'],kind=existing['kind'],
                confidence=existing['confidence'],rationale=existing['rationale'],org_ids=[oid],
                source_group=existing['source_group'],origin=existing['origin'],ai_used=bool(existing['ai_used']),
                review_status=existing['review_status'])
            linked+=1
        else:
            source=con.execute('SELECT * FROM discovery WHERE url_key=?',(e['url_key'],)).fetchone()
            if not source: continue
            from .normalize import classify_rule
            kind,confidence,reason=classify_rule(source['title'],source['summary'],source['source_name'])
            if source['source_group']=='ransomware-leak-monitors':
                kind,confidence,reason='claim',.75,'Ransomware aggregator listing; attacker assertion unverified'
            add_item(con,url=source['url'],title=source['title'],summary=source['summary'],
                source_name=source['source_name'],source_group=source['source_group'],
                published_at=source['published_at'],kind=kind,confidence=confidence,rationale=reason,
                org_ids=[oid]);linked+=1
            # Keep discovery copy for reproducibility; it may be referenced by candidate evidence.
    # Approving a related entity must preserve the documented suggestion. The
    # organization review does not verify the relationship itself.
    con.execute("""INSERT OR IGNORE INTO organization_relations
        (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at)
        SELECT source_org_id,?,relation_type,evidence_url,'unverified',recorded_at
        FROM pending_relation_suggestions WHERE target_candidate_id=? AND source_org_id!=?""",
        (oid,candidate_id,oid))
    con.commit()
    return {'organization_id':oid,'name':row['name'],'linked_publications':linked,
            'note':'Approved as an entity for monitoring, NOT as a verified breach victim.'}


def reject_candidate(con, candidate_id: int) -> None:
    row=con.execute('SELECT status FROM entity_candidates WHERE id=?',(candidate_id,)).fetchone()
    if not row: raise ValueError('Unknown candidate')
    if row['status']=='approved': raise ValueError('Approved candidate cannot be rejected here')
    con.execute("UPDATE entity_candidates SET status='rejected' WHERE id=?",(candidate_id,))
    con.commit()


def runtime_organizations(con, predefined: list[Organization]) -> list[Organization]:
    """Active DB registry plus original aliases; manual edits are persistent."""
    from .registry import has_active, aliases
    previous={o.id:o for o in predefined}
    result=[]
    for row in con.execute('SELECT * FROM organizations ORDER BY name'):
        if not has_active(con,row['id']):continue
        old=previous.get(row['id'])
        named=[row['name']]+list(aliases(con,row['id']))
        if old:named+=list(old.aliases)
        uniq=tuple(dict.fromkeys(x for x in named if x))
        result.append(Organization(id=row['id'],name=row['name'],sector=row['sector'],
                                   country=row['country'],aliases=uniq,notes=row['notes']))
    return result


RELATION_TYPES={'parent','subsidiary','supplier','customer','partner','agency','same_group','other_documented'}


def import_relations(con, path: Path) -> dict:
    """Import cited ties. Neither co-mention nor same sector is a verified business relationship."""
    count=0;errors=[]
    with path.open(encoding='utf-8-sig',newline='') as fp:
        reader=csv.DictReader(fp)
        required={'source_org_id','target_org_id','relation_type','evidence_url','review_status'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV needs '+','.join(sorted(required)))
        for row_idx,row in enumerate(reader,start=2):
            left=(row.get('source_org_id') or '').strip()
            right=(row.get('target_org_id') or '').strip()
            relation=(row.get('relation_type') or '').strip()
            url=(row.get('evidence_url') or '').strip()
            review=(row.get('review_status') or 'unverified').strip()
            if not left or left==right or relation not in RELATION_TYPES or review not in {'unverified','verified'}:
                errors.append(f'Line {row_idx}: invalid relation or organization IDs');continue
            parsed=urlsplit(url)
            if parsed.scheme!='https' or not parsed.hostname or parsed.username or parsed.password:
                errors.append(f'Line {row_idx}: public HTTPS evidence URL required');continue
            found=con.execute('SELECT COUNT(*) FROM organizations WHERE id IN (?,?)',(left,right)).fetchone()[0]
            if found!=2: errors.append(f'Line {row_idx}: unknown org');continue
            cur=con.execute('''INSERT OR IGNORE INTO organization_relations
                (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at,verified_at)
                VALUES (?,?,?,?,?,?,?)''',(left,right,relation,url,review,utc_now(),utc_now() if review=='verified' else None))
            count+=cur.rowcount
    con.commit()
    return {'inserted':count,'errors':errors}


def organization_connections(con, org_id: str, limit: int=15) -> dict:
    org=con.execute('SELECT * FROM organizations WHERE id=?',(org_id,)).fetchone()
    if not org: raise ValueError('Unknown organization')
    limit=max(1,min(int(limit),500))
    documented=con.execute('''SELECT r.*,b.name AS other_name,b.country AS other_country,b.sector AS other_sector,
       b.id AS other_id,
       (SELECT excerpt FROM relation_suggestion_evidence e WHERE e.relation_id=r.id LIMIT 1) AS evidence_excerpt
       FROM organization_relations r
       JOIN organizations b ON b.id=CASE WHEN r.source_org_id=? THEN r.target_org_id ELSE r.source_org_id END
       WHERE r.source_org_id=? OR r.target_org_id=? ORDER BY r.review_status DESC,r.id DESC LIMIT ?''',
       (org_id,org_id,org_id,limit)).fetchall()
    similar=con.execute('''SELECT o.id,o.name,o.country,o.sector,
       (CASE WHEN o.country=? THEN 1 ELSE 0 END + CASE WHEN o.sector=? THEN 1 ELSE 0 END) AS overlaps
       FROM organizations o WHERE o.id!=? AND (o.country=? OR o.sector=?)
       ORDER BY overlaps DESC, o.name LIMIT ?''',
       (org['country'],org['sector'],org_id,org['country'],org['sector'],limit)).fetchall()
    # Distinguish group-wise attributes from confirmed company-to-company relationships.
    co_mentioned=con.execute('''SELECT b.id,b.name,COUNT(DISTINCT i.id) AS articles,MIN(i.url) AS example_url
      FROM mentions a JOIN mentions bb ON a.item_id=bb.item_id AND bb.org_id!=a.org_id
      JOIN organizations b ON b.id=bb.org_id JOIN items i ON i.id=a.item_id
      WHERE a.org_id=? AND i.review_status!='rejected' GROUP BY b.id ORDER BY articles DESC,b.name LIMIT ?''',(org_id,limit)).fetchall()
    pending=con.execute("""SELECT r.*,c.name AS other_name,c.status AS candidate_status
        FROM pending_relation_suggestions r JOIN entity_candidates c ON c.id=r.target_candidate_id
        WHERE r.source_org_id=? AND c.status='pending' ORDER BY r.id DESC LIMIT ?""",(org_id,limit)).fetchall()
    counts=con.execute("""SELECT COUNT(*) AS total,
        COALESCE(SUM(review_status='verified'),0) AS verified
        FROM organization_relations WHERE source_org_id=? OR target_org_id=?""",(org_id,org_id)).fetchone()
    return {'documented':[dict(r) for r in documented],
            'pending':[dict(r) for r in pending],
            'summary':{'documented':counts['total'],'verified':counts['verified'],
                       'unverified':counts['total']-counts['verified'],'pending_entities':len(pending),
                       'state':'documented' if counts['total'] else 'pending_review' if pending else 'no_documented_links',
                       'explanation':'Only cited relationships are shown. Missing links mean unknown coverage, not organizational isolation.'},
            'co_mentioned':[dict(r) for r in co_mentioned],
            'similar':[dict(r) for r in similar],
            'warning':'Similarity is not a supplier, parent-company or attack-chain relationship.'}


def candidate_evidence(con,candidate_id:int,limit:int=20)->list[dict]:
    return [dict(x) for x in con.execute('''SELECT * FROM candidate_evidence WHERE candidate_id=?
      ORDER BY published_at DESC LIMIT ?''',(candidate_id,limit)).fetchall()]


def network_context(con, org_id: str, days: int=30) -> dict:
    """Count only context signals, NEVER propagate attacks or scores between nodes."""
    import datetime as dt
    now=dt.datetime.now(dt.timezone.utc)
    date=(now-dt.timedelta(days=max(1,min(days,365)))).isoformat()
    active="i.kind IN ('claim','threat_statement','incident_report') AND i.review_status!='rejected' AND i.published_at>=? AND i.published_at<=?"
    verified=con.execute(f'''SELECT COUNT(DISTINCT i.id) FROM organization_relations r
      JOIN mentions m ON m.org_id=CASE WHEN r.source_org_id=? THEN r.target_org_id ELSE r.source_org_id END
      JOIN items i ON i.id=m.item_id
      WHERE (r.source_org_id=? OR r.target_org_id=?) AND r.review_status='verified' AND {active}''',
      (org_id,org_id,org_id,date,now.isoformat())).fetchone()[0]
    peers=con.execute(f'''SELECT COUNT(DISTINCT i.id) FROM organizations focal
      JOIN organizations peer ON peer.sector=focal.sector AND peer.id!=focal.id
      JOIN mentions m ON m.org_id=peer.id JOIN items i ON i.id=m.item_id
      WHERE focal.id=? AND {active}''',(org_id,date,now.isoformat())).fetchone()[0]
    return {'days':days,'verified_relations_publications':verified,
            'same_sector_publications':peers,
            'meaning':'Editorial mentions around related/peer organizations, not attacks or exposure. Excluded from individual breach probability.'}


# These patterns describe only explicit, completed or present relationships.
# They deliberately exclude promises, joint news coverage and sector similarity.
_RELATION_PHRASES = (
    ('parent', r"\s*[,—–-]?\s*(?:(?:is|remains)\s+)?(?:a\s+|the\s+)?(?:wholly[- ]owned\s+)?subsidiary\s+of\s+"),
    ('parent', r"\s*[,—–-]?\s*(?:является\s+)?дочерн(?:яя|ей)\s+(?:компани(?:я|ей)|структур(?:а|ой))\s+"),
    ('supplier', r"\s*[,—–-]?\s*(?:(?:is)\s+)?(?:a\s+|the\s+)?supplier\s+(?:to|of)\s+"),
    ('supplier', r"\s*[,—–-]?\s*(?:является\s+)?поставщик(?:ом)?\s+"),
    ('subsidiary', r"\s+(?:has\s+acquired|acquired)\s+"),
    ('subsidiary', r"\s+(?:приобрел[аи]?|купил[аи]?)\s+"),
)
_RELATION_UNCERTAIN = re.compile(
    r"\b(?:not|no|never|former|formerly|rumou?r\w*|denies?|denied|allegedly|reportedly|would|could|may|might|plans?|propos\w*|не|нет|никогда|бывш\w*|якобы|слух\w*|отрица\w*|планиру\w*|может|собира\w*)\b", re.I)


def discover_relation_suggestions(con, organizations=None, limit: int=1000) -> dict:
    """Extract cited, UNVERIFIED typed ties from already retained publications.

    Only exact aliases of organizations already matched to the same item are
    eligible. A short explicit sentence must state the tie; co-mentions never
    become business relationships. Review of the entity is separate from review
    of the relationship. Repeated runs preserve manual verification and dedupe.
    """
    from .config import load_organizations
    from .normalize import clean_markup
    ensure_schema(con)
    if organizations is None:
        organizations=runtime_organizations(con,load_organizations())
    aliases={}
    alias_owners={}
    for org in organizations:
        names={plain(name).strip() for name in (org.name,*org.aliases) if isinstance(name,str)}
        names={name for name in names if len(name)>=3}
        aliases[org.id]=names
        for name in names: alias_owners.setdefault(name,set()).add(org.id)
    # Ambiguous aliases cannot resolve a relationship's endpoints.
    aliases={oid:[name for name in names if len(alias_owners[name])==1]
             for oid,names in aliases.items()}
    rows=con.execute("""SELECT i.* FROM items i
        WHERE i.review_status!='rejected' AND i.origin!='synthetic' AND i.published_at IS NOT NULL
          AND i.published_at<=? AND (SELECT COUNT(*) FROM mentions m WHERE m.item_id=i.id)>=2
        ORDER BY i.published_at DESC,i.id DESC LIMIT ?""",
        (utc_now(),max(1,min(int(limit),10000)))).fetchall()
    result={'examined':len(rows),'inserted':0,'evidence_added':0,'method':'explicit_relationship_sentence'}
    patterns={}
    for row in rows:
        url=urlsplit(row['url'])
        if url.scheme!='https' or not url.hostname or url.username or url.password: continue
        matched=[m[0] for m in con.execute('SELECT org_id FROM mentions WHERE item_id=?',(row['id'],))
                 if m[0] in aliases and aliases[m[0]]]
        if len(matched)>20: continue  # Large directory/list articles are not relationship claims.
        # Keep title and summary separate to avoid joining unrelated sentences.
        sentences=[]
        for part in (row['title'],row['summary']):
            sentences.extend(re.split(r'[.!?;\n]+',clean_markup(part[:24000])))
        for original in sentences:
            sentence=plain(original)
            if len(sentence)>500 or _RELATION_UNCERTAIN.search(sentence): continue
            for left in matched:
                for right in matched:
                    if left==right: continue
                    pair=(left,right)
                    if pair not in patterns:
                        left_names='(?:'+'|'.join(re.escape(a) for a in sorted(aliases[left],key=len,reverse=True)[:20])+')'
                        right_names='(?:'+'|'.join(re.escape(a) for a in sorted(aliases[right],key=len,reverse=True)[:20])+')'
                        patterns[pair]=[(relation,re.compile(r'(?<!\w)'+left_names+r'["«»“”]?'+phrase+
                                            r'["«»“”]?'+right_names+r'(?!\w)'))
                                        for relation,phrase in _RELATION_PHRASES]
                    for relation,pattern in patterns[pair]:
                        if not pattern.search(sentence): continue
                        inserted=con.execute("""INSERT OR IGNORE INTO organization_relations
                            (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at)
                            VALUES(?,?,?,?,'unverified',?)""",(left,right,relation,row['url'],utc_now()))
                        result['inserted']+=inserted.rowcount
                        relation_id=con.execute("""SELECT id FROM organization_relations
                            WHERE source_org_id=? AND target_org_id=? AND relation_type=? AND evidence_url=?""",
                            (left,right,relation,row['url'])).fetchone()[0]
                        evidence=con.execute("""INSERT OR IGNORE INTO relation_suggestion_evidence
                            (relation_id,item_id,excerpt,detection_method) VALUES(?,?,?,?)""",
                            (relation_id,row['id'],original.strip()[:500],result['method']))
                        result['evidence_added']+=evidence.rowcount
    con.commit()
    return result
