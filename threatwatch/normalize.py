"""Text cleanup, date parsing, entity matching, and conservative label detection."""
from __future__ import annotations
import calendar
import datetime as dt
import hashlib
import html
import re
import unicodedata
from email.utils import parsedate_to_datetime
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from .config import Organization

UTC = dt.timezone.utc
CYBER_RE = re.compile(r"\b(?:cyber|hack|hacker|hacktiv|pirat|ddos|dos\b|defac|ransom|ciberataqu|cyberangriff|cyberattacc|ataque inform[aá]tic|datenleck|violazione.*dati|violaç[aã]o.*dados|网络攻击|網絡攻擊|サイバー攻撃|사이버.*공격|кибератак|киберугроз|взлом|хакер|вредонос|шифровальщик|утечк|компрометац|рансом|rançongic|rancongic|breach|fuite de donn|attaque informatique|cyberattaque|intrusion|vol de donn|data leak|website down|indisponib|compromis|malware)\w*", re.I)
CLAIM_RE = re.compile(r"\b(?:revendiqu|claim|affirme|declare|déclare|alleg|annonce|selon|menac|threaten|заявля|утвержда|заявил|сообщил)\w*", re.I)
CONFIRM_RE = re.compile(r"\b(?:confirm|confirmed|confirme|reconnai|a subi|victime d|informe d.un incident|acknowledged|подтверд|подверг|пострадал)\w*", re.I)
DDoS_RE = re.compile(r"\b(?:ddos|d\.d\.o\.s|deni de service|déni de service|overload)\b", re.I)
LEAK_RE = re.compile(r"\b(?:leak|fuite|divulg|vol de donn|data breach|données volées|database|ciberataqu|datenleck|violazione.*dati|violaç[aã]o.*dados|утечк|кража данных|украден.*данн)\w*", re.I)
DEFACE_RE = re.compile(r"\b(?:defac|site piraté|site pirate|site hacked|page modifiée|page modifiee)\w*", re.I)
VULN_RE = re.compile(r"\b(?:vulnérab|vulnerab|cve-\d{4}-\d+|security advisory|avis de sécurité|уязвим|бюллетень безопасности)\w*", re.I)
HACKTIVIST_RE = re.compile(r"\b(?:hacktiv|noname057|no\s*name057|dark storm|cybertroll|opfrance|anonymous)\w*", re.I)


# CJK reports do not have a word boundary before the attack term.
CYBER_RE = re.compile(CYBER_RE.pattern + r"|网络攻击|網絡攻擊|数据泄露|サイバー攻撃|情報漏洩|사이버 ?공격|데이터 ?유출", re.I)
ATTACK_EVENT_RE = re.compile(r"\b(?:cyberattack|ransomware|cyberangriff|cyberattacc|ciberataqu|кибератак|взлом|шифровальщик)\w*|网络攻击|網絡攻擊|数据泄露|サイバー攻撃|情報漏洩|사이버 ?공격|데이터 ?유출", re.I)

# Actual incident language takes precedence over a CVE mentioned as its cause.
# Immediate verb/object grammar keeps generic vulnerability warnings advisory.
DIRECT_INCIDENT_RE = re.compile(
    r"\b(?:confirms?|confirmed|acknowledges?|acknowledged|reports?|reported|suffers?|suffered|hit\s+(?:by|with))"
    r"\s+(?:(?:a|an|the)\s+)?(?:cyber[ -]?attack|data\s+breach|ransomware(?!\s+(?:risk|threat))|ddos(?:\s+attack)?)\b"
    r"|\b(?:подтверд\w*|подверг\w*|пострадал\w*\s+от)\s+(?:кибератак\w*|утечк\w*\s+данных|взлом\w*)"
    r"|\b(?:victime\s+d[’']une?|a\s+subi\s+une?)\s+(?:cyberattaque|attaque\s+informatique)\b", re.I)
_INCIDENT_NEGATION_RE = re.compile(r"\b(?:not|never|no|denies?|denied|не|отрица\w*)\b", re.I)

THREAT_RE = re.compile(r"\b(?:threaten\w*|threats? against|plans? to attack|will attack|menac\w*|угрож\w*|угроз\w*|планиру\w* атак\w*|готов\w* атак\w*)", re.I)


def plain(text: str) -> str:
    """Fold accents and case without deleting non-Latin organization names."""
    normalized = unicodedata.normalize("NFKC", html.unescape(text)).casefold()
    result=[]
    for char in normalized:
        decomposed=unicodedata.normalize("NFKD",char)
        # Accent folding is useful for French aliases, but removing Japanese
        # dakuten or Cyrillic breve changes letters and merges distinct names.
        if unicodedata.name(decomposed[0],"").startswith("LATIN") or char=='ё':
            result.extend(c for c in decomposed if not unicodedata.combining(c))
        else:
            result.append(char)
    return "".join(result)


def clean_markup(text: str) -> str:
    return re.sub(r"\s+", " ", html.unescape(re.sub(r"<[^>]*>", " ", text or ""))).strip()


def utc_now() -> str:
    return dt.datetime.now(UTC).isoformat(timespec="seconds")


def parse_date(value: str | None) -> str | None:
    if not value:
        return None
    try:
        value = value.strip()
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        result = dt.datetime.fromisoformat(value)
    except (ValueError, TypeError):
        try:
            result = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError):
            return None
    if result.tzinfo is None:
        result = result.replace(tzinfo=UTC)
    return result.astimezone(UTC).isoformat(timespec="seconds")


def iso_days_ago(days: int) -> str:
    return (dt.datetime.now(UTC) - dt.timedelta(days=days)).isoformat(timespec="seconds")


def normalize_url(url: str) -> str:
    try:
        p = urlsplit(url.strip())
        if p.scheme not in ("https", "http") or not p.hostname:
            return ""
        query = [(k, v) for k, v in parse_qsl(p.query, keep_blank_values=True)
                 if not (k.startswith("utm_") or k in {"fbclid", "gclid", "ref"})]
        path = p.path.rstrip("/") or "/"
        return urlunsplit((p.scheme.lower(), p.netloc.lower(), path, urlencode(query), ""))
    except (ValueError, AttributeError):
        return ""


def key_for_url(url: str) -> str:
    return hashlib.sha256(normalize_url(url).encode()).hexdigest()


def matching_organizations(text: str, orgs: list[Organization]) -> list[str]:
    normalized = plain(text)
    found = []
    for org in orgs:
        for alias in org.aliases:
            a = plain(alias).strip()
            # Chinese and Japanese words are commonly written without spaces.
            cjk = bool(re.search(r"[\u3400-\u9fff\u3040-\u30ff]", a))
            if len(a) < (2 if cjk else 3):
                continue
            matched = a in normalized if cjk else re.search(r"(?<!\w)" + re.escape(a) + r"(?!\w)", normalized)
            if matched:
                # Avoid interpreting an ordinary-word brand as a cyber incident alone.
                if len(a) <= 5 and not CYBER_RE.search(text):
                    continue
                found.append(org.id)
                break
    return found


def classify_rule(title: str, summary: str, source_name: str = "") -> tuple[str, float, str]:
    text = f"{title} {summary}"
    if not (CYBER_RE.search(text) or VULN_RE.search(text)):
        return "context", 0.40, "No explicit cyber activity detected"
    explicit_incident=any(not _INCIDENT_NEGATION_RE.search(text[max(0,m.start()-35):m.start()])
                          for m in DIRECT_INCIDENT_RE.finditer(text))
    if explicit_incident:
        return "incident_report", 0.65, "Explicitly reported incident; a cited CVE is context, not proof of independent verification"
    if VULN_RE.search(text) and not (DDoS_RE.search(text) or DEFACE_RE.search(text)):
        return "advisory", 0.70, "Generic security advisory; not proof of exposure"
    if THREAT_RE.search(text):
        return "threat_statement", 0.55, "Explicit public threat; target and attribution require review"
    if CLAIM_RE.search(text) and (DDoS_RE.search(text) or LEAK_RE.search(text) or DEFACE_RE.search(text)):
        return "claim", 0.65, "Reported or attributed claim; not independently confirmed"
    if CONFIRM_RE.search(text) and (DDoS_RE.search(text) or LEAK_RE.search(text) or DEFACE_RE.search(text)):
        return "incident_report", 0.65, "Reported incident; publisher is not independent verification"
    if DDoS_RE.search(text) or LEAK_RE.search(text) or DEFACE_RE.search(text):
        return "incident_report", 0.45, "Cyber incident mentioned, confirmation unknown"
    if ATTACK_EVENT_RE.search(text) and CONFIRM_RE.search(text):
        return "incident_report", 0.60, "Reported attack; publication and affected entity require review"
    return "context", 0.45, "Contextual cyber-related information"


def title_similarity(a: str, b: str) -> float:
    def tokens(s: str) -> str:
        return " ".join(sorted(set(re.findall(r"[^\W_]{3,}", plain(s)))))
    left, right = tokens(a), tokens(b)
    return SequenceMatcher(None, left, right).ratio() if left and right else 0.0


def source_domain(url: str) -> str:
    host = urlsplit(url).hostname or "unknown"
    return host[4:] if host.startswith("www.") else host


def safe_date(date_iso: str | None) -> str:
    return (date_iso or "")[:10]
