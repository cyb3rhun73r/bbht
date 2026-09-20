# bugbounty-intel

A local, searchable bug-bounty research and payload-intelligence tool for
**authorized security testing** - bug bounty programs, labs, and
infrastructure you own. Combines publicly disclosed HackerOne Hacktivity
data, OWASP Top 10 / CWE mappings, and curated payload references (from
PortSwigger's Web Security Academy and PayloadsAllTheThings) into one
searchable local SQLite database.

Read `docs/safety.md` before use. This tool defaults to **PASSIVE/OFFLINE**
mode and never sends an active request unless you configure `scope.yaml`
and explicitly opt into `SAFE_ACTIVE` mode - and even then, only
`safe_for_automation: true` payloads run automatically. `RESTRICTED`-risk
payloads (credential theft, destructive SQL, reverse shells, etc.) are
stored as reference only and are never auto-executed.

## Install

```bash
cd bugbounty-intel
pip install -e .
```

## Quickstart

```bash
# Load the curated offline payload dataset (works with no network/credentials)
bugbounty-intel sync

# Search
bugbounty-intel search "SSTI"
bugbounty-intel search "IDOR" --hackerone   # needs HackerOne sync first

# Browse a category
bugbounty-intel payloads xss
bugbounty-intel category A05
bugbounty-intel cwe CWE-79

# Correlate: payload -> CWE -> OWASP -> HackerOne precedent -> PortSwigger reference
bugbounty-intel correlate ssti
bugbounty-intel correlate xss

# Export
bugbounty-intel export --format json
bugbounty-intel export --format csv --category sqli
bugbounty-intel export-intruder category xss
```

## HackerOne sync (optional, needs your own API token)

```bash
export HACKERONE_API_USERNAME=your-h1-username
export HACKERONE_API_TOKEN=your-h1-api-token
bugbounty-intel sync --source hackerone
```

See `docs/sources.md`.

## Docker

```bash
docker build -t bugbounty-intel .
docker run --rm -it -v bugbounty-intel-data:/root/.bugbounty-intel bugbounty-intel sync
docker run --rm -it -v bugbounty-intel-data:/root/.bugbounty-intel bugbounty-intel payloads xss
```

Or with compose (the service's entrypoint is already `bugbounty-intel`, so just pass subcommand args):

```bash
docker compose run --rm bugbounty-intel sync
docker compose run --rm bugbounty-intel search SSTI
```

The named volume `bugbounty-intel-data` persists the SQLite database
between runs.

## Status

See `docs/architecture.md` for which of the spec's 6 implementation phases
are done vs. scaffolded.
