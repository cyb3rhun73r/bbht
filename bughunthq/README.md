# Bug Hunt HQ (desktop)

A Windows desktop app (Python + Tkinter, packaged as a single `.exe` with
PyInstaller) that automates the recon → triage step of bug hunting:

- Passive + light-active subdomain enumeration (crt.sh, plus `subfinder`/`amass`
  if you already have them on PATH) and liveness/tech-fingerprint checks.
- Crawls live hosts, mines JS bundles for hidden endpoints, and flags possible
  hardcoded secrets.
- Discovers URL parameters and runs safe, single-request checks for reflected
  input and open redirects.
- Checks for common exposures: `.git/HEAD`, `.env`, Swagger/OpenAPI specs,
  GraphQL endpoints, WordPress user enumeration, missing security headers.
- **Smart suggestions:** turns every recon signal into a ranked (P1–P5) attack
  hypothesis with a ready-to-copy command for the matching tool (sqlmap,
  dalfox, ffuf, wpscan, git-dumper, GraphQL introspection, etc). Commands are
  never run automatically — you review, then Copy or Run them yourself, and
  Run only works if the tool is already installed and you've checked the
  authorization box.
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
4. Your app is at `dist\BugHuntHQ.exe` — copy it anywhere and double-click to run.

No Python installation is needed on machines that only *run* the built exe.

## Optional external tools

Bug Hunt HQ shells out to these tools **only when you click Run**, and only
if they're already on your PATH. Install whichever you want the "Run" button
to work for; everything else still shows a copyable command:

| Tool | Used for | Project |
|---|---|---|
| subfinder | extra passive subdomain sources | https://github.com/projectdiscovery/subfinder |
| amass | extra passive subdomain sources | https://github.com/owasp-amass/amass |
| sqlmap | SQL injection confirmation | https://github.com/sqlmapproject/sqlmap |
| dalfox | reflected/DOM XSS confirmation | https://github.com/hahwul/dalfox |
| ffuf | fuzzing (LFI params, directories) | https://github.com/ffuf/ffuf |
| nuclei | template-based vuln scanning | https://github.com/projectdiscovery/nuclei |
| wpscan | WordPress-specific scanning | https://github.com/wpscanteam/wpscan |
| git-dumper | dumping an exposed `.git` directory | https://github.com/arthaud/git-dumper |

On Windows, most Go-based tools (subfinder, nuclei, ffuf) install with
`go install <module>@latest` once Go is installed; sqlmap and wpscan are a
`pip install` / `gem install` away; see each project's own README for
current install instructions.

## How the suggestion engine decides

Rules live in `bughunthq.py` under `build_suggestions()` — e.g. a parameter
named `id`/`search`/`sort` is flagged as a SQLi candidate, `redirect`/`next`/
`url` as open-redirect/SSRF candidates, `file`/`path`/`page` as LFI
candidates, an exposed `.env` as P1, a missing security header as P5, and so
on. Tune `SQLI_PARAM_HINTS`, `LFI_PARAM_HINTS`, etc. at the top of the file
to match your own methodology.
