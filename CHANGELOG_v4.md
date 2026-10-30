# v4.0 — Incident-first expansion

- Added candidate organization ledger (`entity_candidates`, `candidate_evidence`) discovered from structured claim listings, explicit manual labels and limited title grammar; all candidates require human approval.
- Approved organizations are saved in SQLite and dynamically included in future feed matching and scoring. Legacy static watchlist remains compatible.
- Added `/incidents`, `/candidates`, `/analytics`; country/industry filters on overview, candidate list, and incident feed.
- Added `organization_relations` with mandatory cited URLs and distinct review states; separate views for documented ties, co-mentions and same-sector/country peers.
- Added optional Wikidata QID relationship suggestions, never silently verified.
- Added public GDELT DOC API, global Ransomfeed feed, Ransomwhere metadata and broader international news sources; disabled expensive per-organization Google searches by default.
- Added `discover-entities`, `entities`, `approve-entity`, `reject-entity`, `connections`, `import-relations`, `enrich-wikidata`, `import-incidents`, exports for entities and relations.
- Keeps local Ollama and OpenAI **optional**; LLM output remains unverified and never triggers auto-approval.
- Maintains existing v3.2 historical snapshots and probability-of-public-claims module. No individual breach probabilities are generated without independently verified outcomes.
