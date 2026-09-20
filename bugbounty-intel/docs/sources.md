# Data sources

## HackerOne Hacktivity (`src/collectors/hackerone.py`)

Requires your own credentials, set as environment variables:

```bash
export HACKERONE_API_USERNAME=your-h1-username
export HACKERONE_API_TOKEN=your-h1-api-token
```

Get an API token from your HackerOne account settings. This tool never
ships or stores credentials. Current docs:
https://api.hackerone.com/hacker-resources/

Rate limiting: exponential backoff + `Retry-After` handling is implemented
in `fetch_page()`. Only publicly disclosed reports should be synced/stored -
respect the program's disclosure settings and HackerOne's API terms.

## PortSwigger Web Security Academy (`src/collectors/portswigger.py`)

This collector intentionally does **not** scrape portswigger.net live.
Instead, `data/payloads/*.json` contains a hand-curated set of the canonical
payloads documented on each cheat sheet, each with a `source_url` pointing
at the exact page. Refresh by hand when a cheat sheet changes - the
collector module just lists the reference pages for you to diff against.

## PayloadsAllTheThings (`src/collectors/payloadsallthethings.py`)

Public repo: https://github.com/swisskyrepo/PayloadsAllTheThings

The collector fetches the repo's top-level category list and README files
via the GitHub API/raw content, for you to review and curate new entries
from - it does not bulk-import every file (the project spec explicitly
prohibits that in §6, since the repo mixes prose, curl commands, and payload
snippets in inconsistent per-directory formats).

## Seed dataset (`data/payloads/*.json`)

The bundled seed set is what `bugbounty-intel sync` (default `--source seeds`)
loads, fully offline. Every entry has a `source_id`/`source_url` pointing at
where it's documented publicly. Extend these files directly to add more
curated payloads - see the schema in `src/database/schema.sql` and the
project spec §7.
