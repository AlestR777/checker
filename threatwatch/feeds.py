"""Passive, rate-limited retrieval of public RSS/Atom feeds; no target connections."""
from __future__ import annotations
import logging
import re
import time
from dataclasses import dataclass
from urllib.parse import urlencode, urlsplit
from xml.etree import ElementTree as ET
from .normalize import clean_markup, normalize_url, parse_date, source_domain
from .network import fetch_bytes
from .config import Organization

LOG = logging.getLogger(__name__)
USER_AGENT = "ThreatWatchEducational/0.1 (+offline educational OSINT prototype; RSS only)"


@dataclass(frozen=True)
class Article:
    title: str
    summary: str
    url: str
    published_at: str | None
    source_name: str
    source_group: str


def google_rss(query: str, locale: str = "fr") -> str:
    locales={"fr":("fr","FR"),"en":("en","US"),"de":("de","DE"),"it":("it","IT"),
             "es":("es","ES"),"pl":("pl","PL"),"nl":("nl","NL"),
             "ru":("ru","RU"),"pt":("pt-BR","BR"),"ja":("ja","JP"),
             "ko":("ko","KR"),"zh":("zh-TW","TW")}
    language,country=locales.get(locale,("en","US"))
    params=urlencode({"q":query,"hl":language,"gl":country,"ceid":f"{country}:{language}"})
    return "https://news.google.com/rss/search?"+params


def source_definitions(sources: list[dict], orgs: list[Organization]) -> list[tuple[str,str,int]]:
    expanded: list[tuple[str,str,int]] = []
    for s in sources:
        if s["type"] in {"ransomfeed_api", "ransomlook_api", "ransomware_live_api", "ransomwhere_api", "gdelt_doc"}:
            continue  # JSON API handled separately in collect_feeds
        if s["type"] == "rss":
            expanded.append((s["name"], s["url"], int(s.get("max_items", 50))))
        elif s["type"] == "google_news":
            expanded.append((s["name"], google_rss(s["query"], s.get("locale", "fr")), int(s.get("max_items", 50))))
        elif s["type"] in {"google_org_search", "google_org_context"}:
            # An optional explicit subset avoids a request for every organization
            # in a large watchlist. Without it, keep the documented full-watchlist
            # behavior; never silently truncate the user's selected organizations.
            selected = set(s['org_ids']) if 'org_ids' in s else None
            for org in orgs:
                if selected is not None and org.id not in selected:
                    continue
                # Search canonical names plus a few *explicit* aliases; scoring still
                # requires conservative entity matching against article text.
                canonical=[org.name]
                canonical += [a for a in org.aliases if a.lower()!=org.name.lower() and len(a)>=6][:2]
                names=' OR '.join('"'+a.replace('"','')+'"' for a in canonical)
                query=f'({names}) {s.get("query_suffix", "cyberattaque")}' 
                expanded.append((s["name"]+" / "+org.name, google_rss(query, s.get('locale', 'fr')), int(s.get("max_items", 15))))
    # Preserve existing source IDs/preferences while fetching shared RSS
    # endpoints only once (e.g. the legacy and current The Record entries).
    unique = {}
    for name, url, limit in expanded:
        key = normalize_url(url)
        if key in unique:
            old_name, old_url, old_limit = unique[key]
            unique[key] = (old_name, old_url, max(old_limit, limit))
        else:
            unique[key] = (name, url, limit)
    return list(unique.values())


def fetch_rss(url: str, timeout: int = 18, max_bytes: int = 2_000_000) -> bytes:
    return fetch_bytes(url, timeout=timeout, max_bytes=max_bytes)


def _subtext(elem: ET.Element, name: str) -> str:
    node = elem.find(name)
    return "" if node is None else "".join(node.itertext()).strip()


def parse_feed(xml_data: bytes, feed_name: str, max_items: int = 50) -> list[Article]:
    probe = xml_data[:300].lstrip().lower()
    if not probe or probe.startswith((b'<!doctype html',b'<html')):
        raise ValueError('Expected XML/RSS but server returned an HTML page or empty body; verify source URL')
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as exc:
        raise ValueError('Invalid RSS/XML response; verify feed URL: '+str(exc)) from exc
    if root.tag.lower().endswith('html'):
        raise ValueError('Expected an RSS/Atom feed, received HTML instead')
    articles: list[Article] = []
    is_atom = root.tag.endswith("feed")
    if is_atom:
        entries = root.findall("{http://www.w3.org/2005/Atom}entry")
        for item in entries[:max_items]:
            title = _subtext(item,"{http://www.w3.org/2005/Atom}title")
            summary = _subtext(item,"{http://www.w3.org/2005/Atom}summary") or _subtext(item,"{http://www.w3.org/2005/Atom}content")
            links = item.findall("{http://www.w3.org/2005/Atom}link")
            link = next((x.attrib.get("href","") for x in links if x.attrib.get("rel","alternate")=="alternate"), "")
            date = _subtext(item,"{http://www.w3.org/2005/Atom}published") or _subtext(item,"{http://www.w3.org/2005/Atom}updated")
            author = _subtext(item,"{http://www.w3.org/2005/Atom}author/{http://www.w3.org/2005/Atom}name")
            link = normalize_url(link)
            if title and link:
                articles.append(Article(clean_markup(title),clean_markup(summary),link,parse_date(date),author or feed_name,source_domain(link)))
        return articles
    entries = root.findall("./channel/item") or root.findall(".//item")
    for item in entries[:max_items]:
        title = clean_markup(_subtext(item,"title"))
        summary = clean_markup(_subtext(item,"description") or _subtext(item,"{http://purl.org/rss/1.0/modules/content/}encoded"))
        link = normalize_url(_subtext(item,"link"))
        date = _subtext(item,"pubDate") or _subtext(item,"{http://purl.org/dc/elements/1.1/}date")
        src_node = item.find("source")
        label = (src_node.text or "").strip() if src_node is not None else feed_name
        src_link = src_node.attrib.get("url","") if src_node is not None else ""
        group = source_domain(src_link) if src_link else source_domain(link)
        if title and link:
            articles.append(Article(title,summary,link,parse_date(date),label or feed_name,group))
    return articles


def collect_feeds(sources: list[dict], orgs: list[Organization], delay: float = 1.25, skip_names=None):
    """Yield (source_name, articles, error). Only preconfigured public syndication endpoints."""
    from .ransomfeed import load_claims
    from .claim_sources import load_claim_source
    from .social_sources import load_mastodon, load_telegram
    from .gdelt import load_articles
    from .ransomwhere import load_victims
    skip_names=set(skip_names or ())
    gdelt_limited=False
    jobs = []
    for name, url, limit in source_definitions(sources, orgs):
        jobs.append((name, 'rss', url, limit,{}))
    for src in sources:
        if src['type'] in {'ransomfeed_api','ransomlook_api','ransomware_live_api','ransomwhere_api','mastodon_tag','telegram_public','gdelt_doc'}:
            jobs.append((src['name'], src['type'], src.get('url',''), int(src.get('max_items',100)),src))
    for idx, (name, kind, url, limit, src) in enumerate(jobs):
        if name in skip_names or (kind=='gdelt_doc' and gdelt_limited):
            yield name, [], 'SKIPPED_COOLDOWN: source in network/rate-limit cooldown; later runs will retry'
            continue
        if idx and delay:
            time.sleep(delay)
        try:
            if kind == 'ransomfeed_api':
                articles = load_claims(url, name, limit)
            elif kind in {'ransomlook_api','ransomware_live_api'}:
                articles = load_claim_source(kind,url,name,limit,timeout=int(src.get('timeout',35)))
            elif kind == 'ransomwhere_api':
                articles = load_victims(url,name,limit)
            elif kind == 'gdelt_doc':
                articles = load_articles(src)
            elif kind == 'mastodon_tag':
                articles = load_mastodon(src)
            elif kind == 'telegram_public':
                articles = load_telegram(src)
            else:
                articles = parse_feed(fetch_rss(url), name, limit)
            yield name, articles, None
        except Exception as exc:
            if kind=='gdelt_doc' and ('429' in str(exc) or 'Too Many Requests' in str(exc)):
                gdelt_limited=True
            LOG.warning('Could not read %s: %s', name, exc)
            yield name, [], str(exc)
