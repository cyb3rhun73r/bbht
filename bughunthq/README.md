# Bug Hunt HQ (desktop)

A Windows desktop app (Python + Tkinter, packaged as a single `.exe` with
PyInstaller) that automates the recon → triage step of bug hunting:

- Passive + light-active subdomain enumeration (crt.sh, plus `subfinder`/`amass`
  when bundled or on PATH) and liveness/tech-fingerprint checks.
- Crawls live hosts, mines JS bundles for hidden endpoints, and flags possible
  hardcoded secrets.
- Discovers URL parameters and runs safe, single-request checks for reflected
  input and open redirects.
- Checks for common exposures: `.git/HEAD`, `.env`, Swagger/OpenAPI specs,
  GraphQL endpoints, WordPress user enumeration, missing security headers.
- **Smart suggestions, mapped to OWASP and MITRE ATT&CK:** turns every recon
  signal into a ranked (P1–P5) attack hypothesis, tagged with its OWASP Top 10
  (2021) category, its OWASP API Security Top 10 (2023) category where the
  finding is API-shaped, and the MITRE ATT&CK (Enterprise) technique it maps
  to once exploited — plus a ready-to-copy command for the matching tool.
  Commands are never run automatically — you review, then Copy or Run them
  yourself, and Run only works once you've checked the authorization box.
- **Tools are bound into the app**, not something you install separately:
  `tools\fetch_tools.py` downloads official Windows binaries for the
  compiled tools and vendors the pure-Python ones as source, all into a
  `tools\` folder that ships next to `BugHuntHQ.exe` and that the app checks
  automatically before falling back to PATH. `build.bat` runs this for you.
- A findings log with severity/status tracking and one-click Markdown export.
- Projects save/load as plain `.json` files on your machine — nothing is sent
  anywhere except the domain you scan and crt.sh for passive lookups.

**Authorized testing only.** This tool sends real HTTP requests to the domain
you enter. Only point it at assets you own or are explicitly authorized to
test (an in-scope bug bounty asset, a client engagement, or your own lab).

## Run it from source (any OS)

```
cd bughunthq
python -m venv .venv
# Windows:  .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python bughunthq.py
```

## Build BugHuntHQ.exe on Windows 11

PyInstaller builds for the OS it runs on, so the `.exe` has to be built *on
a Windows machine* (it can't be cross-compiled from Linux/macOS):

1. Install Python 3.10+ from python.org, checking "Add python.exe to PATH".
2. Copy this `bughunthq` folder onto your Windows 11 machine.
3. Open Command Prompt in that folder and run `build.bat`.
   - This also runs `tools\fetch_tools.py`, which downloads/vendors the
     attack tools below into `tools\` and copies that folder next to the exe.
4. Your app is the whole `dist\` folder — `BugHuntHQ.exe` plus `dist\tools\`
   beside it. Copy/zip/share the folder as a unit; double-click the exe to run.

No Python installation is needed on machines that only *run* the built app —
the exe carries its own interpreter, including for the vendored Python tools.

## Bound attack tools — OWASP Top 10 (2021) coverage

`tools\fetch_tools.py` (run automatically by `build.bat`, or run it yourself
any time to update) fetches these straight into `tools\`, and the app checks
that folder before PATH, so "Run" on a suggestion works out of the box:

| OWASP category | Tool | Used for | How it's bundled | Project |
|---|---|---|---|---|
| A01 Broken Access Control | ffuf | directory/LFI-param fuzzing | official Windows binary | https://github.com/ffuf/ffuf |
| A01 Broken Access Control | corsy | CORS misconfiguration | vendored source | https://github.com/s0md3v/Corsy |
| A02 Cryptographic Failures | tlsx | TLS/cipher-suite checks | official Windows binary | https://github.com/projectdiscovery/tlsx |
| A03 Injection | sqlmap | SQL injection confirmation | vendored source | https://github.com/sqlmapproject/sqlmap |
| A03 Injection | dalfox | reflected/DOM XSS confirmation | official Windows binary | https://github.com/hahwul/dalfox |
| A03 Injection | commix | OS command injection | vendored source | https://github.com/commixproject/commix |
| A05 Security Misconfiguration | nuclei | template-based misconfig/CVE scanning | official Windows binary | https://github.com/projectdiscovery/nuclei |
| A05 Security Misconfiguration | git-dumper | dumping an exposed `.git` directory | vendored source | https://github.com/arthaud/git-dumper |
| A06 Vulnerable & Outdated Components | trivy | dependency/component vuln scanning (e.g. on git-dumper's loot) | official Windows binary | https://github.com/aquasecurity/trivy |
| A06 Vulnerable & Outdated Components | wpscan | WordPress plugin/theme/core CVEs | *not bundled — see below* | https://github.com/wpscanteam/wpscan |
| A07 Identification & Auth Failures | jwt_tool | JWT alg-confusion / tampering | vendored source | https://github.com/ticarpi/jwt_tool |
| A10 Server-Side Request Forgery | interactsh-client | out-of-band callback listener for blind SSRF/XXE | official Windows binary | https://github.com/projectdiscovery/interactsh |
| (recon) | subfinder | extra passive subdomain sources | official Windows binary | https://github.com/projectdiscovery/subfinder |

A04 Insecure Design, A08 Software/Data Integrity Failures and A09 Security
Logging & Monitoring Failures don't have a single matching offensive tool —
they're methodology/manual-review findings, and the checklist side of Bug
Hunt HQ (see the Artifact version) covers them step by step.

**wpscan** is not bundled — it needs a Ruby runtime, a poor fit for a
single-folder bundle. Install it separately (`gem install wpscan`) if you
want that suggestion runnable; otherwise Copy still gives you the command to
run in your own terminal. **amass** is likewise left to PATH if you prefer
it over the bundled subfinder — same reasoning, optional extra.

Re-running `fetch_tools.py` skips anything already vendored and re-downloads
the latest release binaries, so it's safe to use as an "update tools" step.

## How the suggestion engine decides

Rules live in `bughunthq.py` under `build_suggestions()` — e.g. a parameter
named `id`/`search`/`sort` is flagged as a SQLi candidate, `redirect`/`next`/
`url` as open-redirect/SSRF candidates, `file`/`path`/`page` as LFI
candidates, an exposed `.env` as P1, a missing security header as P5, and so
on. Tune `SQLI_PARAM_HINTS`, `LFI_PARAM_HINTS`, etc. at the top of the file
to match your own methodology.

## Framework mappings: OWASP + MITRE ATT&CK

Every suggestion carries three tags, each resolved from a small dict near
the top of `bughunthq.py` so they're easy to keep current as the frameworks
update:

- **`OWASP`** — OWASP Top 10 (2021), the current stable web-application list.
- **`OWASP_API`** — OWASP API Security Top 10 (2023), applied alongside the
  web Top 10 on findings that are API-shaped (SSRF, CORS, JWT, broken
  function-level authz, GraphQL/Swagger inventory exposure).
- **`MITRE`** — MITRE ATT&CK (Enterprise) technique/sub-technique IDs, e.g.
  `T1190 Exploit Public-Facing Application` for SQLi/command injection,
  `T1552.005 Unsecured Credentials: Cloud Instance Metadata API` for SSRF,
  `T1505.003 Server Software Component: Web Shell` for unrestricted upload,
  `T1606 Forge Web Credentials` for JWT tampering. This tells you not just
  *what* the finding is, but where it sits in an actual attacker's
  tactic/technique chain — useful when a report needs to speak both bug
  bounty and enterprise-red-team language.

When OWASP or MITRE publish a new revision, update the `OWASP`, `OWASP_API`
or `MITRE` dict in `bughunthq.py` (and the `owasp="..."`/`mitre="..."` codes
passed into each `self._sug(...)` call in `build_suggestions()`) — nothing
else in the app needs to change.
