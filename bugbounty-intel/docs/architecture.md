# Architecture

```
Collectors
   │
   ├── HackerOne (src/collectors/hackerone.py)      - live API, needs your credentials
   ├── PortSwigger (src/collectors/portswigger.py)   - reference pages only, curated by hand
   └── PayloadsAllTheThings (src/collectors/payloadsallthethings.py) - repo listing, curated by hand
          │
          ▼
      Normalizer (src/normalizers/seed_loader.py)
          │
          ▼
      Dedup (src/database/db.py: upsert_payload dedupes on category + normalized_payload)
          │
          ▼
        SQLite (src/database/schema.sql)
          │
          ▼
       CLI (src/cli/main.py: sync / search / category / cwe / report / payloads / export)
```

## Implementation status vs. the 6-phase plan in the project spec

- **Phase 1** (SQLite, payload schema, OWASP/CWE taxonomy, CLI): done.
- **Phase 2** (PayloadsAllTheThings + PortSwigger sourcing, dedup, provenance): done, via a curated seed dataset rather than live scraping (see docs/sources.md for why).
- **Phase 3** (HackerOne Hacktivity collector, pagination, normalization): collector implemented, needs your own API credentials to run live.
- **Phase 4** (correlation, search): basic full-text search implemented (`search`, `category`, `cwe` commands). Payload -> CWE -> OWASP -> HackerOne report correlation (§47) is partially wired via shared CWE/OWASP tags; a dedicated `correlate` command is a good next addition.
- **Phase 5** (scope engine, safety engine, OAST config): scope guard and request-mode enforcement implemented (`src/safety/scope.py`); actual SAFE_ACTIVE HTTP execution engine is not yet wired to the CLI - this is the natural next piece to add once you have a real, authorized target to validate it against.
- **Phase 6** (web UI, Burp exports, analytics dashboard): CSV/JSON/Markdown export and a `safe_for_automation`-filtered Intruder wordlist export are implemented; the React web UI is not built.
