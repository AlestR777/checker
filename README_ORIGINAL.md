# v5.2 update

See `UPDATE_V5_2_RU.md` and `CHANGELOG_v5_2.md` for the new region-scoped sources, dark UI, reversible web organization management, human candidate review and provenance-aware relation graph. Optional AI remains off by default.

# ThreatWatch Global v5.1 — one-click Windows launch

Double-click `START_THREATWATCH.bat` to open the localhost dashboard, begin passive collection, and activate the six-hour schedule. AI is always off by default. Stop the app by closing its console. Copy your own `data/threatwatch.db` from an earlier version after stopping all old processes; the archive contains no personal database. See [Russian user guide](README_RU.md) and [v5.1 changelog](CHANGELOG_v5_1.md).

---

# ThreatWatch Global v5.0 — incident-first OSINT, graph context and validation

Defensive/local threat-monitoring prototype. Adds **independent human entity-extraction audit**, **point-in-time graph context**, and **paired chronologically embargoed comparison** of direct-only vs direct+graph predictive features. AI remains strictly **opt-in**. No active targeting or system scanning. No promise of real-world breach probabilities.

### Quick start

```bash
python -m pip install -r requirements.txt
python -m threatwatch init
python -m threatwatch run
python -m threatwatch serve
```

For the quality and evaluation workflows see **[README_RU.md](README_RU.md)** and **[CHANGELOG_v5.md](CHANGELOG_v5.md)**.

```bash
python -m threatwatch export-entity-audit exports/entity_review.csv --size 100
python -m threatwatch evaluate-entity-audit exports/entity_review.csv
python -m threatwatch prepare-graph-history exports/graph_unlabelled.csv
python -m threatwatch validate-graph exports/graph_verified.csv
```

**Strict historical evaluation requires observed ingestion and entity-link dates, 28-day lookback, complete 14-day outcome horizon, independently reviewed positives *and* negatives, and a sufficiently diverse set of labelled snapshots.** The package ships no real incident-outcome training data.

---

# ThreatWatch v4 — Incident-first public cybersecurity monitoring

This is a **local educational/defensive OSINT** project. It reads public RSS and documented metadata APIs, records provenance, discovers candidate organizations from publicly named incidents and provides country/industry filters and reviewable relationship suggestions. Optional Ollama/OpenAI classification is disabled by default. **It does not probe company infrastructure or verify breaches.** Monitoring indices are **not calibrated breach probabilities**.

See [README_RU.md](README_RU.md) for setup, migration, CLI examples, historical-model limitations, and the new Incident Feed / Candidates / Analytics panels.

```bash
python -m pip install -r requirements.txt
python -m threatwatch init
python -m threatwatch discover-entities
python -m threatwatch run
python -m threatwatch serve
```

**v3.2 migration:** back up and copy `data/threatwatch.db` into this new project folder before running `init`. Tables are added without deleting existing evidence.

Sources include Ransomfeed, RansomLook, Ransomwhere, The Record, Google News, GDELT DOC 2.0, CERT-FR, ZATAZ, Securelist and more. Sources are independently configurable in `sources.json`; public network availability is not guaranteed and requires a real run.
