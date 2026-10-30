"""OPTIONAL source-backed public Wikidata corporate relationship suggestions.

No fuzzy lookup, no scanning and no automatic assertion of trust. The operator
must supply the exact Wikidata QID corresponding to an already known organization.
"""
from __future__ import annotations
import re
from .network import fetch_json
from .normalize import utc_now, key_for_url
from .entity_graph import _candidate,entity_key,ensure_schema,runtime_organizations

PROPERTIES={'P749':'parent','P355':'subsidiary','P127':'other_documented'}

def get_qid_data(qid: str) -> dict:
    if not re.fullmatch(r'Q[1-9][0-9]{0,10}',qid):
        raise ValueError('Expected an explicit Wikidata QID, e.g. Q123')
    uri=f'https://www.wikidata.org/wiki/Special:EntityData/{qid}.json'
    payload=fetch_json(uri,timeout=20,max_bytes=3_000_000,allowed_hosts={'www.wikidata.org'})
    entity=payload.get('entities',{}).get(qid)
    if not isinstance(entity,dict):
        raise ValueError('Wikidata did not return the specified QID')
    return entity


def _label(entity:dict)->str:
    labels=entity.get('labels',{})
    for lang in ('en','fr','ru'):
        v=labels.get(lang)
        if isinstance(v,dict) and v.get('value'):
            return str(v['value']).strip()[:140]
    for lang in sorted(labels):
        value=labels[lang]
        if isinstance(value,dict) and value.get('value'):
            return str(value['value']).strip()[:140]
    return ''


def _names(entity: dict) -> set[str]:
    """Exact labels and declared aliases across languages; no fuzzy entity merging."""
    result=set()
    for label in entity.get('labels',{}).values():
        if isinstance(label,dict) and isinstance(label.get('value'),str):
            result.add(entity_key(label['value']))
    for aliases in entity.get('aliases',{}).values():
        if not isinstance(aliases,list): continue
        for alias in aliases:
            if isinstance(alias,dict) and isinstance(alias.get('value'),str):
                result.add(entity_key(alias['value']))
    return {name for name in result if len(name)>=3 or (len(name)>=2 and re.search(r'[\u3400-\u9fff\u3040-\u30ff]',name))}


def _matching_orgs(con, entity: dict) -> list[str]:
    names=_names(entity)
    from .config import load_organizations
    return [org.id for org in runtime_organizations(con,load_organizations())
            if any(entity_key(alias) in names for alias in org.aliases)]


def extract_relationship_qids(entity:dict)->list[dict]:
    result=[];seen=set()
    claims=entity.get('claims',{})
    for prop,relation in PROPERTIES.items():
        for claim in claims.get(prop,[])[:15]:
            if claim.get('rank')=='deprecated':continue
            try: target=claim['mainsnak']['datavalue']['value']['id']
            except (KeyError,TypeError):continue
            if not isinstance(target,str) or not re.fullmatch(r'Q[1-9][0-9]{0,10}',target):continue
            if (target,relation) in seen:continue
            seen.add((target,relation));result.append({'target_qid':target,'relation_type':relation,'property':prop})
    return result[:12]


def suggest_wikidata_links(con, org_id: str, qid: str, *, limit: int=8) -> dict:
    """Explicit opt-in. No relation is considered verified just because Wikidata states it."""
    ensure_schema(con)
    row=con.execute('SELECT id,name FROM organizations WHERE id=?',(org_id,)).fetchone()
    if not row:raise ValueError('Unknown organization')
    record=get_qid_data(qid)
    wikidata_name=_label(record)
    identity_matches=_matching_orgs(con,record)
    if not wikidata_name or identity_matches!=[org_id]:
        raise ValueError('QID label differs from organization name; verify identity manually before importing')
    results=[]
    for link in extract_relationship_qids(record)[:max(1,min(limit,12))]:
        other=get_qid_data(link['target_qid'])
        other_name=_label(other)
        if not other_name:continue
        evidence_url=f'https://www.wikidata.org/wiki/{qid}'
        proof_key=key_for_url('https://www.wikidata.org/wiki/'+link['target_qid'])
        matches=_matching_orgs(con,other)
        if len(matches)>1:
            results.append({'name':other_name,'relation':link['relation_type'],'status':'ambiguous_identity','url':evidence_url})
            continue
        if matches==[org_id]: continue
        if matches:
            target_id=matches[0]
            con.execute('''INSERT OR IGNORE INTO organization_relations
              (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at)
              VALUES (?,?,?,?,?,?)''',(org_id,target_id,link['relation_type'],evidence_url,'unverified',utc_now()))
            results.append({'name':other_name,'relation':link['relation_type'],'status':'unverified_link','url':evidence_url})
        else:
            _candidate(con,other_name,'','','wikidata_related_entity',
                       url='https://www.wikidata.org/wiki/'+link['target_qid'],
                       url_key=proof_key,published_at=None,source_name='Wikidata',source_group='wikidata.org',kind='relation_context')
            candidate=con.execute('SELECT id,status,reviewed_org_id FROM entity_candidates WHERE name_key=?',
                                  (entity_key(other_name),)).fetchone()
            if not candidate: continue
            if candidate['status']=='approved' and candidate['reviewed_org_id']!=org_id:
                con.execute("""INSERT OR IGNORE INTO organization_relations
                    (source_org_id,target_org_id,relation_type,evidence_url,review_status,recorded_at)
                    VALUES(?,?,?,?,'unverified',?)""",
                    (org_id,candidate['reviewed_org_id'],link['relation_type'],evidence_url,utc_now()))
                status='unverified_link'
            elif candidate['status']=='pending':
                con.execute("""INSERT OR IGNORE INTO pending_relation_suggestions
                    (source_org_id,target_candidate_id,relation_type,evidence_url,source_qid,target_qid,recorded_at)
                    VALUES(?,?,?,?,?,?,?)""",
                    (org_id,candidate['id'],link['relation_type'],evidence_url,qid,link['target_qid'],utc_now()))
                status='pending_review'
            else: status='rejected_entity'
            results.append({'name':other_name,'relation':link['relation_type'],'status':status,'url':evidence_url})
    con.commit()
    return {'source':row['name'],'qid':qid,'suggestions':results,'note':'Wikidata relations are not verified attack links.'}
