"""Local-only, reversible source and organization preferences.

No destructive organization deletion: historical evidence remains available.
All changes are explicit user actions; approved entities are not breach confirmations.
"""
from __future__ import annotations
import json
import re
import sqlite3
import hashlib
from .normalize import utc_now
from .config import Organization, load_sources

SCHEMA = """
CREATE TABLE IF NOT EXISTS organization_preferences (
 org_id TEXT PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
 active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
 aliases_json TEXT NOT NULL DEFAULT '[]',
 origin TEXT NOT NULL DEFAULT 'seed',
 changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS source_preferences (
 source_id TEXT PRIMARY KEY,
 enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
 changed_at TEXT NOT NULL
);
"""

def ensure(con: sqlite3.Connection):
    con.executescript(SCHEMA)


def has_active(con, org_id: str) -> bool:
    x=con.execute('SELECT active FROM organization_preferences WHERE org_id=?',(org_id,)).fetchone()
    return x is None or bool(x[0])


def activate(con, org_id: str, active: bool):
    if not con.execute('SELECT 1 FROM organizations WHERE id=?',(org_id,)).fetchone():
        raise ValueError('Неизвестная организация')
    con.execute('''INSERT INTO organization_preferences(org_id,active,aliases_json,origin,changed_at)
      VALUES (?,?,'[]','existing',?) ON CONFLICT(org_id) DO UPDATE SET
      active=excluded.active,changed_at=excluded.changed_at''',(org_id,int(active),utc_now()))
    con.commit()


def manual_add(con, *, name: str, country: str, sector: str, aliases: str='', notes: str='') -> str:
    name=' '.join(name.split()); country=country.strip().upper();sector=' '.join(sector.split())
    if not 3<=len(name)<=130:raise ValueError('Название: от 3 до 130 символов')
    if not re.fullmatch(r'[A-Z]{2}',country):raise ValueError('Страна: ISO-2, например FR')
    if not 2<=len(sector)<=100:raise ValueError('Отрасль: от 2 до 100 символов')
    if len(notes)>1200:raise ValueError('Слишком длинная заметка')
    alias_list=[x.strip() for x in aliases.replace(';','|').split('|') if x.strip()]
    if len(alias_list)>15 or any(len(x)>100 for x in alias_list):raise ValueError('Не более 15 вариантов названия')
    existing=con.execute('SELECT id FROM organizations WHERE lower(name)=lower(?)',(name,)).fetchone()
    if existing:raise ValueError('Организация уже существует; используй восстановление или редактирование')
    key=hashlib.sha256((name.casefold()+'|'+country).encode()).hexdigest()[:14]
    oid='manual-'+key
    con.execute('INSERT INTO organizations(id,name,sector,country,notes) VALUES(?,?,?,?,?)',(oid,name,sector,country,notes))
    con.execute('''INSERT INTO organization_preferences(org_id,active,aliases_json,origin,changed_at)
      VALUES(?,1,?,'manual',?)''',(oid,json.dumps(alias_list,ensure_ascii=False),utc_now()))
    con.commit()
    return oid


def change_details(con, org_id: str, *, name:str,country:str,sector:str,aliases:str='',notes:str=''):
    if not con.execute('SELECT 1 FROM organizations WHERE id=?',(org_id,)).fetchone():
        raise ValueError('Неизвестная организация')
    name=' '.join(name.split()); country=country.strip().upper();sector=' '.join(sector.split())
    if not 3<=len(name)<=130 or not re.fullmatch('[A-Z]{2}',country) or not 2<=len(sector)<=100:raise ValueError('Проверь название, ISO-2 и отрасль')
    if len(notes)>1200:raise ValueError('Заметка слишком длинная')
    alias_list=[x.strip() for x in aliases.replace(';','|').split('|') if x.strip()]
    if len(alias_list)>15 or any(len(x)>100 for x in alias_list):raise ValueError('Некорректные псевдонимы')
    conflict=con.execute('SELECT id FROM organizations WHERE lower(name)=lower(?) AND id!=?',(name,org_id)).fetchone()
    if conflict: raise ValueError('Название уже занято')
    con.execute('UPDATE organizations SET name=?,country=?,sector=?,notes=? WHERE id=?',(name,country,sector,notes,org_id))
    old=con.execute('SELECT origin,active FROM organization_preferences WHERE org_id=?',(org_id,)).fetchone()
    con.execute('''INSERT INTO organization_preferences(org_id,active,aliases_json,origin,changed_at)
     VALUES (?,?,?,?,?) ON CONFLICT(org_id) DO UPDATE SET aliases_json=excluded.aliases_json, changed_at=excluded.changed_at''',
     (org_id,old['active'] if old else 1,json.dumps(alias_list,ensure_ascii=False),old['origin'] if old else 'edited',utc_now()))
    con.commit()


def aliases(con, org_id: str) -> list[str]:
    row=con.execute('SELECT aliases_json FROM organization_preferences WHERE org_id=?',(org_id,)).fetchone()
    if not row:return []
    try: return [str(x) for x in json.loads(row[0]) if isinstance(x,str)]
    except (ValueError,TypeError):return []


def all_sources(con):
    defs=load_sources(include_disabled=True)
    overrides={r['source_id']:bool(r['enabled']) for r in con.execute('SELECT source_id,enabled FROM source_preferences')}
    for s in defs:
        s['enabled']=overrides.get(s['id'],bool(s.get('enabled',True)))
        s['scope']=s.get('scope') or ('FR' if ('france' in s['name'].lower() or 'french' in s['name'].lower() or 'cert-fr' in s['id'] or s['id'].startswith(('zataz','01net','google-fr','ransomfeed-fr'))) else 'GLOBAL')
    return defs


def active_sources(con):
    return [s for s in all_sources(con) if s['enabled']]


def source_toggle(con, source_id:str, enabled: bool):
    if source_id not in {s['id'] for s in load_sources(include_disabled=True)}:
        raise ValueError('Источник не найден в каталоге')
    con.execute('''INSERT INTO source_preferences(source_id,enabled,changed_at) VALUES(?,?,?)
      ON CONFLICT(source_id) DO UPDATE SET enabled=excluded.enabled,changed_at=excluded.changed_at''',
      (source_id,int(enabled),utc_now()))
    con.commit()


def bulk_scope(con, scope:str, enable:bool):
    if scope not in {'FR','GLOBAL','EU','US','GB','DE','IT','ES','PL','NL'}: raise ValueError('Неизвестная группа источников')
    targets=[s['id'] for s in all_sources(con) if s['scope']==scope]
    for ident in targets:
        con.execute('''INSERT INTO source_preferences(source_id,enabled,changed_at) VALUES(?,?,?)
          ON CONFLICT(source_id) DO UPDATE SET enabled=excluded.enabled,changed_at=excluded.changed_at''',
          (ident,int(enable),utc_now()))
    con.commit()
    return len(targets)
