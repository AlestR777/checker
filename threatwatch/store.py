"""SQLite evidence ledger. Individual source items never become verified incidents by default."""
from __future__ import annotations
import sqlite3
from pathlib import Path
from typing import Any
from .normalize import utc_now, key_for_url, source_domain, title_similarity, safe_date
from .config import Organization

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS organizations (
 id TEXT PRIMARY KEY, name TEXT NOT NULL, sector TEXT NOT NULL,
 country TEXT NOT NULL, notes TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS items (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 url TEXT NOT NULL UNIQUE, url_key TEXT NOT NULL UNIQUE,
 title TEXT NOT NULL, summary TEXT NOT NULL,
 source_name TEXT NOT NULL, source_domain TEXT NOT NULL,
 source_group TEXT NOT NULL DEFAULT '',
 published_at TEXT, collected_at TEXT NOT NULL,
 kind TEXT NOT NULL, confidence REAL NOT NULL, rationale TEXT NOT NULL,
 origin TEXT NOT NULL DEFAULT 'feed',
 review_status TEXT NOT NULL DEFAULT 'unreviewed',
 ai_used INTEGER NOT NULL DEFAULT 0,
 cluster_id INTEGER,
 FOREIGN KEY(cluster_id) REFERENCES clusters(id)
);
CREATE TABLE IF NOT EXISTS mentions (
 item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 org_id TEXT NOT NULL REFERENCES organizations(id),
 linked_at TEXT,
 PRIMARY KEY(item_id, org_id)
);
CREATE TABLE IF NOT EXISTS clusters (
 id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT NOT NULL REFERENCES organizations(id),
 event_kind TEXT NOT NULL, anchor_date TEXT NOT NULL,
 anchor_title TEXT NOT NULL, created_at TEXT NOT NULL,
 UNIQUE(org_id,event_kind,anchor_date,anchor_title)
);
CREATE TABLE IF NOT EXISTS cluster_members (
 cluster_id INTEGER NOT NULL REFERENCES clusters(id) ON DELETE CASCADE,
 item_id INTEGER NOT NULL REFERENCES items(id) ON DELETE CASCADE,
 PRIMARY KEY(cluster_id,item_id)
);
CREATE TABLE IF NOT EXISTS scores (
 org_id TEXT NOT NULL REFERENCES organizations(id),
 computed_at TEXT NOT NULL, score INTEGER,
 completeness REAL NOT NULL, status TEXT NOT NULL, breakdown_json TEXT NOT NULL,
 PRIMARY KEY(org_id,computed_at)
);
CREATE INDEX IF NOT EXISTS idx_items_published ON items(published_at);
CREATE INDEX IF NOT EXISTS idx_mentions_org ON mentions(org_id);
CREATE INDEX IF NOT EXISTS idx_clusters_org ON clusters(org_id);
CREATE INDEX IF NOT EXISTS idx_scores_org ON scores(org_id,computed_at DESC);
CREATE TABLE IF NOT EXISTS source_checks (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 checked_at TEXT NOT NULL,
 source_name TEXT NOT NULL,
 source_group TEXT NOT NULL,
 status TEXT NOT NULL CHECK(status IN ('ok','error')),
 fetched INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_source_checks_time ON source_checks(checked_at);
CREATE TABLE IF NOT EXISTS discovery (
  url_key TEXT PRIMARY KEY, url TEXT NOT NULL, title TEXT NOT NULL,
  summary TEXT NOT NULL DEFAULT '', source_name TEXT NOT NULL,
  source_group TEXT NOT NULL, published_at TEXT NOT NULL,
  kind TEXT NOT NULL, candidate_name TEXT NOT NULL DEFAULT '',
  collected_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_discovery_date ON discovery(published_at);
CREATE TABLE IF NOT EXISTS discovery_suggestions (
 url_key TEXT PRIMARY KEY REFERENCES discovery(url_key) ON DELETE CASCADE,
 organization_names_json TEXT NOT NULL, relevant_to_france INTEGER NOT NULL,
 suggested_kind TEXT NOT NULL, rationale TEXT NOT NULL,
 model TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS page_texts (
 item_id INTEGER PRIMARY KEY REFERENCES items(id) ON DELETE CASCADE,
 extracted_text TEXT NOT NULL DEFAULT '', status TEXT NOT NULL,
 fetched_at TEXT NOT NULL, error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS org_briefs (
 org_id TEXT PRIMARY KEY REFERENCES organizations(id),
 fingerprint TEXT NOT NULL, text TEXT NOT NULL, created_at TEXT NOT NULL,
 model TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS cybermap_observations (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 observed_date TEXT NOT NULL,
 country TEXT NOT NULL,
 category TEXT NOT NULL,
 measurement TEXT NOT NULL,
 value REAL NOT NULL,
 unit TEXT NOT NULL,
 source_url TEXT NOT NULL,
 captured_at TEXT NOT NULL,
 analyst_note TEXT NOT NULL DEFAULT '',
 UNIQUE(observed_date,country,category,measurement,source_url)
);
CREATE INDEX IF NOT EXISTS idx_cybermap_observed ON cybermap_observations(observed_date DESC);
CREATE TABLE IF NOT EXISTS runs (
 id INTEGER PRIMARY KEY AUTOINCREMENT, started_at TEXT NOT NULL, finished_at TEXT,
 sources_checked INTEGER NOT NULL DEFAULT 0, fetched INTEGER NOT NULL DEFAULT 0,
 inserted INTEGER NOT NULL DEFAULT 0, errors TEXT NOT NULL DEFAULT ''
);
"""


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(str(path), timeout=15)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.executescript(SCHEMA)
    # Schema migrations for v1-v4 databases. NULL means legacy linkage time is
    # unknowable; strict v5 graph snapshots must NOT backdate these mentions.
    columns={r[1] for r in con.execute('PRAGMA table_info(mentions)')}
    if 'linked_at' not in columns:
        con.execute('ALTER TABLE mentions ADD COLUMN linked_at TEXT')
        # As of the upgrade we can attest the link EXISTS in the ledger. This
        # is NOT its historical discovery time; strictly earlier cutoffs exclude it.
        con.execute('UPDATE mentions SET linked_at=? WHERE linked_at IS NULL',(utc_now(),))
    from .entity_graph import ensure_schema
    ensure_schema(con)
    from .registry import ensure as ensure_registry
    ensure_registry(con)
    return con


def upsert_organizations(con: sqlite3.Connection, orgs: list[Organization]) -> None:
    for o in orgs:
        con.execute("INSERT INTO organizations (id,name,sector,country,notes) VALUES (?,?,?,?,?) "
                    "ON CONFLICT(id) DO NOTHING",
                    (o.id,o.name,o.sector,o.country,o.notes))
    con.commit()


def _find_cluster(con: sqlite3.Connection, org_id: str, kind: str, date_iso: str, title: str) -> int:
    # Conservative grouping: same organization, same kind, within two days,
    # and sufficiently similar title. Each source remains individually auditable.
    date = safe_date(date_iso) or "undated"
    if date == "undated":
        con.execute("INSERT INTO clusters (org_id,event_kind,anchor_date,anchor_title,created_at) VALUES (?,?,?,?,?)",
                    (org_id,kind,date,title,utc_now()))
        return int(con.execute("SELECT last_insert_rowid()").fetchone()[0])
    candidates = con.execute("""SELECT id,anchor_date,anchor_title FROM clusters
       WHERE org_id=? AND event_kind=? AND anchor_date BETWEEN date(?,'-2 days') AND date(?,'+2 days')""",
       (org_id,kind,date,date)).fetchall()
    for c in candidates:
        if title_similarity(c["anchor_title"], title) >= 0.76:
            return int(c["id"])
    con.execute("INSERT INTO clusters (org_id,event_kind,anchor_date,anchor_title,created_at) VALUES (?,?,?,?,?)",
                (org_id,kind,date,title,utc_now()))
    return int(con.execute("SELECT last_insert_rowid()").fetchone()[0])


def add_item(con: sqlite3.Connection, *, url: str, title: str, summary: str,
             source_name: str, published_at: str | None, kind: str,
             confidence: float, rationale: str, org_ids: list[str],
             source_group: str = "", origin: str = "feed", ai_used: bool = False,
             review_status: str = "unreviewed") -> bool:
    if not url or not title:
        raise ValueError("A valid source URL and title are required")
    existing = con.execute("SELECT id FROM items WHERE url_key=?", (key_for_url(url),)).fetchone()
    if existing:
        # The same article may mention several organizations added in separate rows.
        # Link the new organizations without duplicating the article itself.
        item_id = int(existing["id"])
        changed = False
        for org_id in sorted(set(org_ids)):
            if con.execute("SELECT 1 FROM mentions WHERE item_id=? AND org_id=?", (item_id,org_id)).fetchone():
                continue
            con.execute("INSERT INTO mentions (item_id,org_id,linked_at) VALUES (?,?,?)", (item_id,org_id,utc_now()))
            cluster = _find_cluster(con,org_id,kind,published_at or "",title)
            con.execute("INSERT INTO cluster_members (cluster_id,item_id) VALUES (?,?)", (cluster,item_id))
            changed = True
        con.commit()
        return False  # Insertion counts unique articles, even if new mentions linked.
    cur = con.execute("""INSERT INTO items
      (url,url_key,title,summary,source_name,source_domain,source_group,published_at,collected_at,
       kind,confidence,rationale,origin,review_status,ai_used)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
      (url,key_for_url(url),title[:350],summary[:4000],source_name,source_domain(url),
       source_group or source_domain(url),published_at,utc_now(),kind,max(0,min(1,confidence)),
       rationale[:500],origin,review_status,int(ai_used)))
    item_id = int(cur.lastrowid)
    for org_id in sorted(set(org_ids)):
        con.execute("INSERT INTO mentions (item_id,org_id,linked_at) VALUES (?,?,?)", (item_id,org_id,utc_now()))
        cluster = _find_cluster(con,org_id,kind,published_at or "",title)
        con.execute("INSERT INTO cluster_members (cluster_id,item_id) VALUES (?,?)", (cluster,item_id))
    con.commit()
    return True


def recent_items(con: sqlite3.Connection, org_id: str, since: str | None = None,
                 until: str | None = None, limit: int = 300) -> list[sqlite3.Row]:
    sql = """SELECT i.*,m.org_id,cm.cluster_id AS event_id FROM items i
             JOIN mentions m ON m.item_id=i.id
             LEFT JOIN cluster_members cm ON cm.item_id=i.id
             LEFT JOIN clusters c ON c.id=cm.cluster_id AND c.org_id=m.org_id
             WHERE m.org_id=? AND (c.org_id=? OR cm.cluster_id IS NULL)"""
    args: list[Any] = [org_id,org_id]
    if since:
        sql += " AND i.published_at>=?"
        args.append(since)
    if until:
        sql += " AND i.published_at<=?"
        args.append(until)
    sql += " ORDER BY COALESCE(i.published_at,i.collected_at) DESC LIMIT ?"
    args.append(limit)
    return con.execute(sql, args).fetchall()


def event_groups(con: sqlite3.Connection, org_id: str, since: str) -> list[dict]:
    rows = con.execute("""SELECT c.id,c.event_kind,c.anchor_date,c.anchor_title,
      COUNT(DISTINCT i.id) AS article_count,COUNT(DISTINCT i.source_group) AS independent_sources,
      MAX(i.confidence) AS max_confidence,
      SUM(CASE WHEN i.review_status='confirmed' THEN 1 ELSE 0 END) AS confirmed_count,
      SUM(CASE WHEN i.review_status='rejected' THEN 1 ELSE 0 END) AS rejected_count
      FROM clusters c JOIN cluster_members cm ON cm.cluster_id=c.id
      JOIN items i ON cm.item_id=i.id
      WHERE c.org_id=? AND i.published_at>=?
      GROUP BY c.id ORDER BY c.anchor_date DESC""", (org_id,since)).fetchall()
    return [dict(r) for r in rows]


def latest_scores(con: sqlite3.Connection) -> list[sqlite3.Row]:
    return con.execute("""SELECT o.*,s.score,s.completeness,s.status,s.computed_at,s.breakdown_json
      FROM organizations o LEFT JOIN organization_preferences pref ON pref.org_id=o.id LEFT JOIN scores s ON s.org_id=o.id AND s.computed_at=(
        SELECT MAX(s2.computed_at) FROM scores s2 WHERE s2.org_id=o.id)
      WHERE COALESCE(pref.active,1)=1 ORDER BY s.score DESC, o.name COLLATE NOCASE""").fetchall()


def save_score(con: sqlite3.Connection, org_id: str, score: int | None,
               completeness: float, status: str, breakdown_json: str) -> None:
    con.execute("""INSERT OR REPLACE INTO scores
      (org_id,computed_at,score,completeness,status,breakdown_json) VALUES (?,?,?,?,?,?)""",
      (org_id,utc_now(),score,completeness,status,breakdown_json))
    con.commit()


def review_item(con: sqlite3.Connection, item_id: int, status: str) -> bool:
    if status not in {"unreviewed", "confirmed", "rejected", "disputed"}:
        raise ValueError("Unknown review status")
    cur = con.execute("UPDATE items SET review_status=? WHERE id=?", (status,item_id))
    con.commit()
    return cur.rowcount > 0


def add_discovery(con: sqlite3.Connection, *, url: str, title: str, summary: str,
                  source_name: str, source_group: str, published_at: str, kind: str,
                  candidate_name: str = '') -> bool:
    """Save unmatched open-source material for analyst triage; no auto-target creation."""
    if not url or not title or not published_at:
        return False
    cur = con.execute("""INSERT OR IGNORE INTO discovery
    (url_key,url,title,summary,source_name,source_group,published_at,kind,candidate_name,collected_at)
    VALUES (?,?,?,?,?,?,?,?,?,?)""",(
        key_for_url(url),url,title[:350],summary[:1000],source_name,
        source_group,published_at,kind,candidate_name[:140],utc_now()))
    con.commit()
    return cur.rowcount > 0
