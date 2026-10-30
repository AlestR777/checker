"""Command-line interface: run, watch, import, export, review, demo, serve."""
from __future__ import annotations
import argparse
import csv
import datetime as dt
import json
import logging
import os
import signal
import sys
import time
from pathlib import Path
from .ai import VALID_KINDS
from .config import ROOT,load_env,load_organizations,load_sources,database_path
from .dashboard import serve
from .demo import populate
from .normalize import normalize_url,parse_date,source_domain,utc_now
from .pipeline import run_once
from .scoring import recompute_all,compare_windows
from .store import connect,upsert_organizations,add_item,review_item,latest_scores, recent_items

LOG = logging.getLogger(__name__)


def initialize(con):
    orgs=load_organizations()
    upsert_organizations(con,orgs)
    # Merely opening the dashboard or a summary must NOT create fake score-history points.
    missing=[o.id for o in orgs if not con.execute(
        'SELECT 1 FROM scores WHERE org_id=? LIMIT 1',(o.id,)).fetchone()]
    if missing:
        recompute_all(con,missing)
    return orgs


def import_csv(con,path: Path) -> dict:
    ids={row['id'] for row in con.execute('SELECT id FROM organizations')}
    added=0; errors=[]
    with path.open("r",encoding="utf-8-sig",newline="") as file:
        for lineno,row in enumerate(csv.DictReader(file),start=2):
            try:
                org_id=(row.get("org_id") or "").strip()
                if org_id not in ids:
                    raise ValueError("Unknown org_id")
                kind=(row.get("kind") or "claim").strip()
                if kind not in VALID_KINDS:
                    raise ValueError("Unknown kind")
                date=parse_date(row.get("published_at"))
                if not date:
                    raise ValueError("Missing/invalid published_at, use ISO 8601")
                url=normalize_url(row.get("url") or "")
                if not url:
                    raise ValueError("Public source URL required")
                title=(row.get("title") or "").strip()
                if not title:
                    raise ValueError("Missing title")
                group=(row.get("source_group") or source_domain(url)).strip()
                status=(row.get("review_status") or "unreviewed").strip()
                if status not in {"unreviewed","confirmed","rejected","disputed"}:
                    raise ValueError("Invalid review_status")
                success=add_item(con,url=url,title=title,summary=row.get("summary") or "",
                                 source_name=row.get("source_name") or source_domain(url),
                                 source_group=group,published_at=date,kind=kind,confidence=.6,
                                 rationale="Manually curated with attached URL; verification status separate",
                                 org_ids=[org_id],origin="manual",review_status=status)
                added+=int(success)
            except (KeyError,ValueError) as exc:
                errors.append(f"line {lineno}: {exc}")
    recompute_all(con,sorted(ids))
    return {"added":added,"errors":errors}


def import_incident_csv(con,path: Path)->dict:
    """Import publicly citable metadata, including organizations NOT on the watchlist."""
    from .store import add_discovery
    result={'inserted':0,'errors':[]}
    with path.open('r',encoding='utf-8-sig',newline='') as fp:
        reader=csv.DictReader(fp)
        required={'url','title','published_at','source_name','kind'}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError('CSV needs url,title,published_at,source_name,kind')
        for number,row in enumerate(reader,2):
            try:
                url=normalize_url((row.get('url') or '').strip())
                if not url.startswith('https://'):raise ValueError('Public HTTPS article URL required')
                date=parse_date(row.get('published_at'))
                if not date:raise ValueError('Invalid published_at')
                kind=(row.get('kind') or '').strip()
                if kind not in VALID_KINDS:raise ValueError('Unknown text label')
                title=(row.get('title') or '').strip()
                if not title:raise ValueError('Missing title')
                group=(row.get('source_group') or source_domain(url)).strip()
                result['inserted']+=int(add_discovery(con,url=url,title=title,summary=(row.get('summary') or ''),
                    source_name=row.get('source_name') or source_domain(url),source_group=group,
                    published_at=date,kind=kind,candidate_name=(row.get('candidate_name') or '').strip()))
            except ValueError as exc:
                result['errors'].append(f'line {number}: {exc}')
    from .entity_graph import discover_from_ledger
    result['entity_discovery']=discover_from_ledger(con,limit=20000)
    return result


def export(con,path: Path,kind: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    if kind=="risks":
        from .scoring import assess_all
        orgs={r['id']:dict(r) for r in con.execute('SELECT * FROM organizations')}
        rows=[{**orgs[r['org_id']],**r,'confidence':r['confidence']['level']} for r in assess_all(con)]
        fields=['id','name','country','sector','score','score_max','level','status','confidence','direct_score','related_score','sector_score','model_version']
    elif kind=="scores":
        rows=latest_scores(con)
        fields=["id","name","sector","country","score","completeness","status","computed_at"]
    elif kind=="evidence":
        rows=con.execute("""SELECT i.id,i.title,i.summary,i.url,i.published_at,i.collected_at,
               i.source_name,i.source_group,i.kind,i.confidence,i.origin,i.review_status,m.org_id
               FROM items i JOIN mentions m ON m.item_id=i.id
               ORDER BY i.published_at DESC""").fetchall()
        fields=["id","title","summary","url","published_at","collected_at","source_name",
                "source_group","kind","confidence","origin","review_status","org_id"]
    elif kind=="discovery":
        rows=con.execute("SELECT * FROM discovery ORDER BY published_at DESC").fetchall()
        fields=['url','title','summary','source_name','source_group','published_at','kind','candidate_name','collected_at']
    elif kind=="entities":
        rows=con.execute("SELECT * FROM entity_candidates ORDER BY last_seen DESC").fetchall()
        fields=['id','name_key','name','country','sector','status','first_seen','last_seen','detection_method','reviewed_org_id']
    elif kind=="relations":
        rows=con.execute("SELECT * FROM organization_relations ORDER BY recorded_at DESC").fetchall()
        fields=['id','source_org_id','target_org_id','relation_type','evidence_url','review_status','recorded_at']
    elif kind=="history":
        rows=con.execute("SELECT * FROM scores ORDER BY computed_at DESC").fetchall()
        fields=["org_id","computed_at","score","completeness","status","breakdown_json"]
    else:
        raise ValueError("Unknown export kind")
    if path.suffix.lower()==".json":
        path.write_text(json.dumps([{k:r[k] for k in fields} for r in rows],ensure_ascii=False,indent=2),encoding="utf-8")
    else:
        with path.open("w",newline="",encoding="utf-8-sig") as file:
            writer=csv.DictWriter(file,fieldnames=fields)
            writer.writeheader()
            for r in rows:
                writer.writerow({k:r[k] for k in fields})
    return len(rows)


def print_summary(con):
    from .scoring import assess_all
    names={r['id']:r['name'] for r in con.execute('SELECT id,name FROM organizations')}
    print("\nORG                              INDEX /100   DATA        STATUS")
    print("-"*78)
    for r in sorted(assess_all(con),key=lambda x:-(x['score'] if x['score'] is not None else -1)):
        value=str(r['score']) if r['score'] is not None else 'N/A'
        print(f"{names[r['org_id']][:31]:31}  {value:>5} /100   {r['confidence']['level']:10}  {r['status']}")
    print("\nNOTE: index 0–100 is a monitoring priority, NOT a breach probability.")


def build_parser():
    p=argparse.ArgumentParser(prog="threatwatch",description="Defensive public-source signal monitor")
    from . import __version__
    p.add_argument('--version',action='version',version='ThreatWatch Global '+__version__)
    p.add_argument("--db",help="SQLite database path")
    p.add_argument("--verbose",action="store_true")
    sub=p.add_subparsers(dest="command",required=True)
    sub.add_parser("init",help="Create database and organization watchlist")
    run=sub.add_parser("run",help="Collect public feeds once and score organizations")
    run.add_argument("--ai",action="store_true",help="Optional API classification (requires OPENAI_API_KEY)")
    run.add_argument("--ml",action="store_true",help="Optional trained local text triage")
    run.add_argument("--local-ai",action="store_true",help="OPTIONAL local Ollama entity suggestions; default OFF")
    run.add_argument("--local-ai-limit",type=int,default=5,help="Maximum number of local model suggestions per run")
    run.add_argument("--delay",type=float,default=1.25,help="Pause between RSS requests in seconds")
    run.add_argument("--max-age-days",type=int,default=60)
    watch=sub.add_parser("watch",help="Run now, then every N hours while process remains running")
    watch.add_argument("--every-hours",type=float,default=6)
    watch.add_argument("--ai",action="store_true")
    watch.add_argument("--ml",action="store_true")
    watch.add_argument("--local-ai",action="store_true",help="OPTIONAL Ollama; default OFF")
    watch.add_argument("--local-ai-limit",type=int,default=5)
    watch.add_argument("--delay",type=float,default=1.25)
    sub.add_parser("demo",help="Insert synthetic OFFLINE DEMO records (never real evidence)")
    sub.add_parser("summary",help="Show latest scores in terminal")
    srv=sub.add_parser("serve",help="Start local dashboard and collection controls")
    srv.add_argument("--port",type=int,default=8765)
    desk=sub.add_parser('desktop',help='One-click local browser application')
    desk.add_argument('--port',type=int,default=0,help='Local port; default asks the OS for a free private port')
    incident=sub.add_parser('import-incidents',help='Import public incident headlines without a preselected organization')
    incident.add_argument('file',type=Path)
    imp=sub.add_parser("import-csv",help="Import manually verified public source links")
    imp.add_argument("file",type=Path)
    ex=sub.add_parser("export",help="Export latest scores, evidence or score history")
    ex.add_argument("kind",choices=["risks","scores","evidence","history","discovery","entities","relations"])
    ex.add_argument("file",type=Path)
    review=sub.add_parser("review",help="Human evidence confirmation (does not validate attacker attribution)")
    review.add_argument("item_id",type=int)
    review.add_argument("status",choices=["unreviewed","confirmed","rejected","disputed"])
    val=sub.add_parser('validate-model',help='Temporally evaluate REAL manually labelled incident outcomes')
    val.add_argument('file',type=Path)
    brief=sub.add_parser('brief',help='Print source-backed organization explanation; --ai optionally rephrases')
    brief.add_argument('org_id',help='Organization ID from organizations.json')
    brief.add_argument('--ai',action='store_true')
    brief.add_argument('--local-ai',action='store_true',help='Free local Ollama summary; no OpenAI key')
    brief.add_argument('--force',action='store_true')
    model=sub.add_parser('train-text',help='Train optional text classifier from HUMAN-labelled CSV')
    model.add_argument('file',type=Path)
    model.add_argument('--output',type=Path,default=ROOT/'models'/'text_model.joblib')
    pred=sub.add_parser('classify-text',help='Classify a text passage using local trained model')
    pred.add_argument('text')
    pred.add_argument('--model',type=Path,default=ROOT/'models'/'text_model.joblib')
    ap=sub.add_parser('analyze-pages',help='Classify locally saved editorial page texts')
    ap.add_argument('--ai',action='store_true',help='Optional OpenAI categorization')
    ap.add_argument('--limit',type=int,default=30)
    ap.add_argument('--threshold',type=float,default=.80)
    enrich=sub.add_parser('enrich-pages',help='Fetch public editorial article text from fixed allowlist only')
    enrich.add_argument('--limit',type=int,default=10)
    enrich.add_argument('--delay',type=float,default=2.0)
    enrich.add_argument('--force',action='store_true')
    labels=sub.add_parser('export-text-labels',help='Create CSV for human annotation, no automatic label guessing')
    labels.add_argument('file',type=Path)
    labels.add_argument('--limit',type=int,default=400)
    rec=sub.add_parser('reconcile-discovery',help='Link old unmatched articles after editing organization aliases')
    rec.add_argument('--limit',type=int,default=5000)
    repair=sub.add_parser('repair-links',help='Re-match retained news and discovery after changing names/aliases (no network)')
    repair.add_argument('--limit',type=int,default=20000)
    disc=sub.add_parser('discovery',help='Recent unmatched public-source articles')
    disc.add_argument('--limit',type=int,default=30)
    triage=sub.add_parser('triage-discovery',help='Use local Ollama to suggest entities in unmatched articles (review only)')
    triage.add_argument('--limit',type=int,default=10)
    doc=sub.add_parser('doctor',help='Explain TLS configuration and display source health')
    doc.add_argument('--test-network',action='store_true')
    fc=sub.add_parser('forecast',help='Observed public-claim model, NOT breach probability')
    fc.add_argument('--horizon-days',type=int,default=14)
    ent=sub.add_parser('discover-entities',help='Extract candidate organizations from incident claims; no AI by default')
    ent.add_argument('--limit',type=int,default=5000)
    ent.add_argument('--include-ai-suggestions',action='store_true',help='Use only already-stored, unverified Ollama suggestions')
    ents=sub.add_parser('entities',help='List candidate organizations from incident-first catalog')
    ents.add_argument('--country',default='')
    ents.add_argument('--sector',default='')
    ents.add_argument('--status',choices=['pending','approved','rejected','all'],default='pending')
    ents.add_argument('--limit',type=int,default=50)
    approve=sub.add_parser('approve-entity',help='Review and promote a candidate into monitoring')
    approve.add_argument('id',type=int)
    approve.add_argument('--country',required=True,help='ISO country code, e.g. FR')
    approve.add_argument('--sector',required=True)
    reject=sub.add_parser('reject-entity',help='Reject a false or non-organization candidate')
    reject.add_argument('id',type=int)
    relations=sub.add_parser('import-relations',help='Import public-source-documented organization relationships from CSV')
    relations.add_argument('file',type=Path)
    wd=sub.add_parser('enrich-wikidata',help='Optional public Wikidata corporate relations (explicit QID only)')
    wd.add_argument('org_id')
    wd.add_argument('qid',help='Wikidata ID Q123; verify company identity before running')
    connections=sub.add_parser('connections',help='Show verified/unverified links and same-sector peers separately')
    connections.add_argument('org_id')
    sub.add_parser('history-status',help='Show readiness for chronological incident backtesting')
    history=sub.add_parser("prepare-history",help="Build historical point-in-time UNLABELLED candidate snapshots")
    history.add_argument("file",type=Path,help="CSV output; incidents must be manually labelled")
    history.add_argument("--start",help="First as-of date YYYY-MM-DD (default: earliest observed + 28 days)")
    history.add_argument("--end",help="Last as-of date YYYY-MM-DD (default: today minus 14 days)")
    history.add_argument("--step-days",type=int,default=7)
    history.add_argument("--mode",choices=["strict","retrospective"],default="strict",
                         help="strict uses ONLY evidence collected by as-of date; retrospective for investigation ONLY")
    quality=sub.add_parser('export-entity-audit',help='Sample matched and unmatched articles for human annotation')
    quality.add_argument('file',type=Path)
    quality.add_argument('--size',type=int,default=100)
    quality.add_argument('--seed',type=int,default=42)
    audit=sub.add_parser('evaluate-entity-audit',help='Measure entity extraction against human-annotated texts')
    audit.add_argument('file',type=Path)
    graphs=sub.add_parser('graph-context',help='Point-in-time graph/publication context for one organization')
    graphs.add_argument('org_id')
    graphs.add_argument('--as-of',help='YYYY-MM-DD; default today')
    graph_hist=sub.add_parser('prepare-graph-history',help='STRICT unlabelled history with verified graph context')
    graph_hist.add_argument('file',type=Path)
    graph_hist.add_argument('--start')
    graph_hist.add_argument('--end')
    graph_hist.add_argument('--step-days',type=int,default=7)
    graph_valid=sub.add_parser('validate-graph',help='Compare direct-only and direct+graph on verified history')
    graph_valid.add_argument('file',type=Path)
    cm=sub.add_parser("import-cybermap",help="Import manually transcribed Kaspersky Cybermap country stats with provenance")
    cm.add_argument("file",type=Path)
    cmp=sub.add_parser("compare",help="Compare mentions before/after a specific date")
    cmp.add_argument("--boundary",default="2026-10-16")
    cmp.add_argument("--start",default="2026-10-01")
    cmp.add_argument("--end",default="2026-10-29")
    return p


def main(argv=None):
    args=build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,format="%(levelname)s %(message)s")
    load_env()
    path=database_path(args.db)
    if args.command=='desktop':
        from .integrity import verify_installation
        checked=verify_installation()
        print('Installation integrity: '+checked['status'])
    con=connect(path)
    orgs=initialize(con)
    try:
        if args.command in {"run","watch"} and args.ai and args.local_ai:
            raise ValueError("Choose --ai or --local-ai (both are optional; default is OFF)")
        if args.command=="init":
            print(f"Database initialized: {path}")
        elif args.command=="demo":
            n=populate(con)
            recompute_all(con,[o.id for o in orgs])
            print(f"Added {n} SYNTHETIC records. Not real-world evidence.")
            print_summary(con)
        elif args.command=="run":
            print("Fetching public sources (may take a minute)...")
            result=run_once(con,ai=args.ai,ml=args.ml,local_ai=args.local_ai,local_ai_limit=args.local_ai_limit,delay=max(0,args.delay),max_age_days=args.max_age_days)
            print(json.dumps(result,ensure_ascii=False,indent=2))
            print_summary(con)
        elif args.command=="watch":
            if args.every_hours < .1:
                raise ValueError("--every-hours must be >= 0.1")
            print(f"Watch mode started: once every {args.every_hours} hours. Ctrl+C to stop.")
            try:
                while True:
                    try:
                        result=run_once(con,ai=args.ai,ml=args.ml,local_ai=args.local_ai,local_ai_limit=args.local_ai_limit,delay=max(0,args.delay))
                        print(f"[{utc_now()}] {result}",flush=True)
                    except Exception:
                        LOG.exception("Run failed; next scheduled run will still occur")
                    time.sleep(args.every_hours*3600)
            except KeyboardInterrupt:
                print("Stopped.")
        elif args.command in ('serve','desktop'):
            con.close()
            serve(path,port=args.port,open_browser=args.command=='desktop')
        elif args.command=="summary":
            print_summary(con)
        elif args.command=='import-incidents':
            print(json.dumps(import_incident_csv(con,args.file),ensure_ascii=False,indent=2))
        elif args.command=="import-csv":
            if not args.file.is_file():
                raise FileNotFoundError(args.file)
            print(json.dumps(import_csv(con,args.file),ensure_ascii=False,indent=2))
        elif args.command=="export":
            print(f"Wrote {export(con,args.file,args.kind)} rows to {args.file}")
        elif args.command=="review":
            if not review_item(con,args.item_id,args.status):
                raise ValueError("Unknown item ID")
            recompute_all(con,[o.id for o in orgs])
            print(f"Item {args.item_id}: {args.status} (human review)")
        elif args.command=='discover-entities':
            from .entity_graph import discover_from_ledger
            print(json.dumps(discover_from_ledger(con,limit=args.limit,include_ai=args.include_ai_suggestions),ensure_ascii=False,indent=2))
        elif args.command=='entities':
            from .entity_graph import list_candidates
            rows=list_candidates(con,country=args.country,sector=args.sector,
                                 status='' if args.status=='all' else args.status,limit=args.limit)
            print(json.dumps(rows,ensure_ascii=False,indent=2))
        elif args.command=='approve-entity':
            from .entity_graph import approve_candidate
            result=approve_candidate(con,args.id,country=args.country,sector=args.sector)
            recompute_all(con,[result['organization_id']])
            print(json.dumps(result,ensure_ascii=False,indent=2))
        elif args.command=='reject-entity':
            from .entity_graph import reject_candidate
            reject_candidate(con,args.id)
            print('Candidate rejected; historical evidence preserved.')
        elif args.command=='import-relations':
            from .entity_graph import import_relations
            print(json.dumps(import_relations(con,args.file),ensure_ascii=False,indent=2))
        elif args.command=='enrich-wikidata':
            from .wikidata_relations import suggest_wikidata_links
            print(json.dumps(suggest_wikidata_links(con,args.org_id,args.qid),ensure_ascii=False,indent=2))
        elif args.command=='connections':
            from .entity_graph import organization_connections
            print(json.dumps(organization_connections(con,args.org_id),ensure_ascii=False,indent=2))
        elif args.command=='history-status':
            from .history import readiness
            print(json.dumps(readiness(con),ensure_ascii=False,indent=2))
        elif args.command=='prepare-history':
            from .history import prepare_history
            print(json.dumps(prepare_history(con,args.file,start=args.start,end=args.end,
                    step_days=args.step_days,mode=args.mode),ensure_ascii=False,indent=2))
        elif args.command=='export-entity-audit':
            from .entity_quality import export_review_sample
            print(json.dumps(export_review_sample(con,args.file,size=args.size,seed=args.seed),ensure_ascii=False,indent=2))
        elif args.command=='evaluate-entity-audit':
            from .entity_quality import evaluate_review_sample
            print(json.dumps(evaluate_review_sample(args.file),ensure_ascii=False,indent=2))
        elif args.command=='graph-context':
            import datetime as dt
            from .graph_temporal import graph_context_at
            day=dt.date.fromisoformat(args.as_of) if args.as_of else dt.datetime.now(dt.timezone.utc).date()
            print(json.dumps(graph_context_at(con,args.org_id,day),ensure_ascii=False,indent=2))
        elif args.command=='prepare-graph-history':
            from .graph_temporal import prepare_graph_history
            print(json.dumps(prepare_graph_history(con,args.file,start=args.start,end=args.end,
                     step_days=args.step_days),ensure_ascii=False,indent=2))
        elif args.command=='validate-graph':
            from .graph_model import validate_graph_history
            print(json.dumps(validate_graph_history(args.file),ensure_ascii=False,indent=2))
        elif args.command=='import-cybermap':
            from .cybermap import import_observations
            print(json.dumps(import_observations(con,args.file),ensure_ascii=False,indent=2))
        elif args.command=='validate-model':
            from .calibration import read_labelled_csv, temporal_holdout_report
            samples=read_labelled_csv(args.file)
            print(json.dumps(temporal_holdout_report(samples),ensure_ascii=False,indent=2))
        elif args.command=='brief':
            from .briefs import local_brief,optional_ai_brief
            
            if args.ai and args.local_ai:
                raise ValueError('Choose --ai OR --local-ai')
            if args.local_ai:
                from .local_ai import local_ai_brief
                result=local_ai_brief(con,args.org_id)
            else:
                result=optional_ai_brief(con,args.org_id,force=args.force) if args.ai else local_brief(con,args.org_id)
            print(json.dumps(result,ensure_ascii=False,indent=2))
        elif args.command=='train-text':
            from .text_model import train
            print(json.dumps(train(args.file,args.output),ensure_ascii=False,indent=2))
        elif args.command=='classify-text':
            from .text_model import predict
            print(json.dumps(predict(args.model,args.text),ensure_ascii=False,indent=2))
        elif args.command=='analyze-pages':
            from .fulltext import analyze_saved_pages
            print(json.dumps(analyze_saved_pages(con,ai=args.ai,threshold=max(.5,min(1,args.threshold)),limit=args.limit),ensure_ascii=False,indent=2))
        elif args.command=='enrich-pages':
            from .fulltext import enrich_pages
            print(json.dumps(enrich_pages(con,limit=max(1,min(args.limit,100)),delay=max(0,args.delay),force=args.force),ensure_ascii=False,indent=2))
        elif args.command=='export-text-labels':
            rows=con.execute("""SELECT published_at,title,summary,url FROM items
              UNION SELECT published_at,title,summary,url FROM discovery
              ORDER BY published_at DESC LIMIT ?""",(max(10,min(args.limit,10000)),)).fetchall()
            args.file.parent.mkdir(parents=True,exist_ok=True)
            with args.file.open('w',encoding='utf-8-sig',newline='') as output:
                writer=csv.DictWriter(output,fieldnames=['published_at','title','summary','label','story_group','url'])
                writer.writeheader()
                for row in rows:
                    writer.writerow({'published_at':row['published_at'][:10],'title':row['title'],
                                     'summary':row['summary'],'label':'','story_group':'','url':row['url']})
            print(f'Exported {len(rows)} unlabeled rows. Annotate label yourself before training: {args.file}')
        elif args.command=='reconcile-discovery':
            from .pipeline import reconcile_discovery
            print(json.dumps(reconcile_discovery(con,limit=args.limit),ensure_ascii=False,indent=2))
        elif args.command=='repair-links':
            from .pipeline import reconcile_mentions
            print(json.dumps(reconcile_mentions(con,limit=args.limit),ensure_ascii=False,indent=2))
        elif args.command=='triage-discovery':
            from .local_ai import triage_discovery
            print(json.dumps(triage_discovery(con,args.limit),ensure_ascii=False,indent=2))
        elif args.command=='discovery':
            rows=con.execute('SELECT published_at,title,candidate_name,url FROM discovery ORDER BY published_at DESC LIMIT ?',
                (max(1,min(args.limit,1000)),)).fetchall()
            for r in rows:
                print(f"{r['published_at'][:10]} | {r['candidate_name'] or '-'} | {r['title']} | {r['url']}")
        elif args.command=='doctor':
            import ssl
            from .network import fetch_bytes
            try:
                import truststore
                provider='OS certificate store via truststore'
            except ImportError:
                try:
                    import certifi
                    provider=f'certifi CA bundle: {certifi.where()}'
                except ImportError:
                    provider='Python default certificate store'
            print('TLS provider:',provider)
            print('OpenSSL:',ssl.OPENSSL_VERSION)
            print('Custom CA:',os.environ.get('THREATWATCH_CA_BUNDLE','not set'))
            sql = "SELECT source_name,max(checked_at) AS checked_at,sum(status='error') AS errors FROM source_checks GROUP BY source_name ORDER BY source_name"
            for row in con.execute(sql):
                print(f"{row['source_name']}: {row['checked_at']} / errors={row['errors']}")
            if args.test_network:
                try:
                    content=fetch_bytes('https://www.cert.ssi.gouv.fr/feed/',max_bytes=1200000)
                    print('Verified CERT-FR HTTPS OK:',len(content),'bytes')
                except Exception as exc:
                    print('Verified CERT-FR HTTPS failed:',exc)
        elif args.command=='forecast':
            from .statistics import forecast_from_database
            for org in orgs:
                print(json.dumps({'organization':org.name,**forecast_from_database(con,org.id,horizon_days=args.horizon_days)},ensure_ascii=False))
        elif args.command=="compare":
            print("Count of mentions (not attacks), before/after boundary:")
            for o in orgs:
                print(json.dumps(compare_windows(con,o.id,args.boundary,args.start,args.end),ensure_ascii=False))
    finally:
        try:
            con.close()
        except Exception:
            pass

if __name__=="__main__":
    main()
