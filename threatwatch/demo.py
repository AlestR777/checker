"""Clearly synthetic records for offline demonstration and automated testing."""
from __future__ import annotations
from datetime import datetime, timedelta,timezone
from .store import add_item
from .normalize import utc_now


def populate(con) -> int:
    now = datetime.now(timezone.utc)
    synthetic = [
      ("les-republicains",-2,"claim","DEMO: fictional group mentions a political party", "Example of an unverified forum claim", "Demo Reporter A","demo-a.example"),
      ("les-republicains",-2,"claim","DEMO: fictional group mentions a political party", "A second publisher repeats the allegation", "Demo Reporter B","demo-b.example"),
      ("les-republicains",-9,"incident_report","DEMO: public report on a fictional website incident", "Historical case simulation; not real news", "Demo Reporter C","demo-c.example"),
      ("ville-de-paris",-1,"threat_statement","DEMO: generic hacktivist discussion of a municipality", "No verifiable claim", "Demo Reporter A","demo-a.example"),
      ("ville-de-paris",-6,"context","DEMO: municipality in social news", "Context is not a cyber incident", "Demo Reporter C","demo-c.example"),
      ("edf",-4,"claim","DEMO: claim about a utility portal", "No evidence of successful compromise", "Demo Reporter B","demo-b.example"),
      ("la-poste-mobile",-12,"claim","DEMO: unverified claim about a mobile service", "Synthetic training record", "Demo Reporter C","demo-c.example"),
    ]
    n=0
    for idx,(org,days,kind,title,summary,source,domain) in enumerate(synthetic):
        when = (now+timedelta(days=days)).isoformat(timespec="seconds")
        url = f"https://{domain}/training/{idx}"
        if add_item(con,url=url,title=title,summary=summary,source_name=source,source_group=domain,
                    published_at=when,kind=kind,confidence=.55,rationale="SYNTHETIC DEMO DATA — NOT EVIDENCE",
                    org_ids=[org],origin="synthetic",review_status="unreviewed"):
            n+=1
    return n
