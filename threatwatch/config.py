"""Loading and validation of organization and source watchlists."""
from __future__ import annotations
import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = ROOT / "data" / "threatwatch.db"


@dataclass(frozen=True)
class Organization:
    id: str
    name: str
    sector: str
    country: str
    aliases: tuple[str, ...]
    notes: str = ""


def load_env(path: Path | None = None) -> None:
    """Minimal .env reader; does not replace variables set in the OS."""
    path = path or ROOT / ".env"
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def database_path(cli_path: str | None = None) -> Path:
    return Path(cli_path or os.getenv("THREATWATCH_DB") or DEFAULT_DB).expanduser().resolve()


def load_organizations(path: Path | None = None) -> list[Organization]:
    data = json.loads((path or ROOT / "organizations.json").read_text(encoding="utf-8"))
    ids: set[str] = set()
    result: list[Organization] = []
    for item in data:
        org = Organization(
            id=item["id"], name=item["name"], sector=item["sector"],
            country=item.get("country", "FR"), aliases=tuple(item.get("aliases") or [item["name"]]),
            notes=item.get("notes", ""),
        )
        if org.id in ids or not org.id or not org.aliases:
            raise ValueError(f"Duplicate/invalid organization: {org.id}")
        ids.add(org.id)
        result.append(org)
    return result


def load_sources(path: Path | None = None, *, include_disabled: bool = False) -> list[dict]:
    items = json.loads((path or ROOT / "sources.json").read_text(encoding="utf-8"))
    valid_types = {"rss", "google_news", "google_org_search", "ransomfeed_api", "ransomlook_api", "ransomware_live_api", "mastodon_tag", "telegram_public", "google_org_context", "gdelt_doc", "ransomwhere_api"}
    for item in items:
        if item["type"] not in valid_types:
            raise ValueError(f"Unknown source type: {item['type']}")
        if item["type"] in {"rss", "ransomfeed_api", "ransomlook_api", "ransomware_live_api", "ransomwhere_api"}:
            u = urlsplit(item["url"])
            if u.scheme != "https" or not u.hostname:
                raise ValueError("RSS feeds must be public HTTPS URLs")
        if item['type'] == 'gdelt_doc' and not item.get('query'):
            raise ValueError('GDELT DOC needs a search query')
        if item['type'] == 'mastodon_tag':
            host = urlsplit(item.get('instance',''))
            if host.scheme != 'https' or not host.hostname or host.username or host.password:
                raise ValueError('Mastodon instance must be public HTTPS')
        if item['type'] == 'telegram_public' and not item.get('channel'):
            raise ValueError('Public Telegram source needs a channel ID')
    return items if include_disabled else [i for i in items if i.get("enabled", True)]
