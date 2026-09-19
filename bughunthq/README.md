# Bug Hunt HQ (desktop)

A Windows desktop app (Python + Tkinter, packaged as a single `.exe` with
PyInstaller) that automates the recon → triage step of bug hunting:

- Passive + light-active subdomain enumeration (crt.sh, plus `subfinder`/`amass`
  when bundled or on PATH) and liveness/tech-fingerprint checks.
- Crawls live hosts, mines JS bundles for hidden endpoints, and flags possible
  hardcoded secrets.
- Discovers URL parameters and runs safe, single-request confirmation checks:
  reflection (XSS), open redirect, SSTI (arithmetic-evaluation confirmed, not
  guessed), CRLF/header injection, unkeyed-header cache poisoning, and (only
  when a 429 was actually seen) rate-limit bypass via spoofed source headers.
- Checks for common exposures: `.git/HEAD`, `.env`, Swagger/OpenAPI specs,
  GraphQL endpoints, WordPress user enumeration, missing security headers.
  Any JWT seen in traffic gets its header decoded locally (no extra request)
  to flag a weak/symmetric or `none` algorithm immediately.
- **Attack Chains tab:** aggregates findings that combine into a bigger story
  (e.g. SSRF → cloud metadata credential theft, exposed `.git` + hardcoded
  secrets → credential harvesting, weak JWT + admin path → forged-token
  privilege escalation) with the manual steps to realize each one. This is
  reasoning/reporting only — it never fires a request or chains exploits
  itself.
- **Advanced Tools tab:** a CORS-exploit PoC generator (writes a standalone
  HTML page demonstrating cross-origin credential theft — evidence for a
  report, not something the app does to the target) and a race-condition
  tester (fires N parallel requests at one endpoint you specify, gated behind
  typing the target hostname to confirm — this can cause real duplicate side
  effects, so it's deliberately more friction than everything else here).
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

## Zero-touch prerequisite setup

Nothing needs installing by hand beyond Python itself, and even that's
attempted automatically:

- **`build.bat`** checks for Python; if it's missing and `winget` is
  available (built into Windows 11), it installs Python automatically. It
  then creates the venv, installs `requirements.txt`, fetches every attack
  tool and its own dependencies, fetches the MITRE ATT&CK dataset, and
  builds the exe — one command, start to finish, on a completely clean
  machine.
- **The built app configures itself too.** The **Setup** tab (first tab)
  shows what's present and what isn't, with "Download / Update" buttons for
  the attack tools and the MITRE data — no need to touch a script or a
  terminal, even for someone who only received the built `BugHuntHQ.exe`
  from a teammate rather than building it themselves. On first launch with
  nothing configured yet, the app asks once whether to fetch everything now.
- Every fetch step is **idempotent and safe to re-run** any time you want
  fresher tool binaries or the latest MITRE release — already-vendored
  Python tools and their dependencies are skipped, compiled binaries and the
  ATT&CK dataset are simply re-downloaded at their current version.

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

1. Copy this `bughunthq` folder onto your Windows 11 machine.
2. Open Command Prompt in that folder and run `build.bat`.
   - If Python isn't installed, it installs it via `winget` automatically,
     then asks you to reopen Command Prompt and run `build.bat` again (Windows
     only picks up the updated PATH in a new terminal). If `winget` isn't
     available either, it prints the python.org download link and stops.
   - It then creates the venv, installs `requirements.txt`, runs
     `tools\fetch_tools.py` (attack tools + their own dependencies) and
     `tools\fetch_attack_data.py` (MITRE ATT&CK dataset, ~50MB one-time
     download), and freezes everything — including each vendored tool's own
     pip dependencies, via `tools\extra-packages.txt` — into the exe with
     PyInstaller.
3. Your app is the whole `dist\` folder — `BugHuntHQ.exe` plus `dist\tools\`
   beside it. Copy/zip/share the folder as a unit; double-click the exe to run.

No Python installation is needed on machines that only *run* the built app —
the exe carries its own interpreter, including for the vendored Python tools.
If you instead hand someone the exe without running `fetch_tools.py`/
`fetch_attack_data.py` first, the app's own **Setup** tab fetches everything
on first launch (see above) — building isn't the only path to a fully
configured app.

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

## MITRE ATT&CK is automated, not hand-typed

`tools\fetch_attack_data.py` downloads the **official MITRE ATT&CK
(Enterprise) dataset** straight from
https://github.com/mitre-attack/attack-stix-data (the STIX 2.1 source MITRE
itself publishes) and builds two small local files under
`tools\attack-data\`:

- **`enterprise-attack-index.json`** — every current (non-deprecated)
  technique/sub-technique: ID, name, tactic(s), URL. Once this exists, the
  app resolves every `T####` code against it instead of the hand-typed
  `MITRE` dict, so labels always match the live data. On every "Start
  Recon", the Recon Log reports the loaded ATT&CK version and **flags any
  technique ID this app uses that the dataset doesn't recognize** (renamed
  or deprecated upstream) — so a stale mapping shows up immediately instead
  of silently mislabeling a finding.
- **`webapp-relevant.json`** — a curated subset (recon through
  collection/exfiltration tactics, filtered to web/API/cloud-relevant
  keywords) that powers the new **MITRE Reference** tab: a searchable,
  always-current-if-you-rerun-the-script browsable list of ATT&CK techniques
  relevant to web-app exploitation, independent of what your last recon run
  actually found.

**Export ATT&CK Navigator layer** (button on the Attack Suggestions tab)
turns the current recon's suggestions into a standard [ATT&CK Navigator]
(https://mitre-attack.github.io/attack-navigator/) layer JSON — technique
IDs scored by how many findings hit them, with the finding titles as
comments. Import it at that URL to get the official heat-map visualization
of what this engagement actually touched, ready to drop into a report.

Nothing above is a hard dependency — if you never run
`fetch_attack_data.py`, the app falls back to its built-in `MITRE` dict
(already validated against the live dataset as of this writing) and the
MITRE Reference tab just tells you how to populate it. Re-run the script any
time to pick up MITRE's latest release.
