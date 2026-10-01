# bbht — Bug Bounty Hunting Toolkit

A Claude Code skill + script toolkit for hunting web/API bugs on
authorized bug bounty programs (HackerOne, Bugcrowd, Intigriti) or your
own lab. Built on real disclosed HackerOne reports — actual payloads and
techniques, not generic OWASP text — covering everything from
zero-interaction search-engine recon to IDOR, business logic, and race
conditions.

**Works across your own machines and your team**: clone this repo
anywhere, run `./setup.sh`, and both the scripts and the Claude Code
skill are ready to go. The skill lives in `.claude/skills/` so it loads
automatically in any Claude Code session opened in this repo.

## Hard rule

**Only test targets you are explicitly authorized to test** — an
enrolled bug bounty program's in-scope assets, or your own lab. Every
script and reference file in this toolkit assumes that.

## Quick start

```bash
git clone <this-repo-url>
cd bbht
./setup.sh
```

That installs the Python dependencies (`requests`, `pyjwt`), makes every
script executable, and checks for (optionally installs) the recon tools
`quickwin_scan.sh` benefits from: `subfinder`, `httpx`, `dnsx`, `nuclei`,
`gau`, `subzy`.

Then either:
- **Use it via Claude Code** — open this repo in Claude Code and just
  talk about bug bounty hunting, IDOR, a specific target, etc. The
  `bug-hunting` skill (`.claude/skills/bug-hunting/SKILL.md`) triggers
  automatically and walks through the full workflow.
- **Use the scripts directly**:
  ```bash
  ./scripts/generate_dorks.py <domain>       # Google-dorking query list
  ./scripts/quickwin_scan.sh <domain>        # automated low-hanging-fruit sweep
  ./scripts/tracker.py program add --name "..." --platform hackerone
  ```

## What's included

### `.claude/skills/bug-hunting/` — the Claude Code skill
`SKILL.md` ties together a full workflow (program selection → recon →
Google dorking → low-hanging fruit → access control/auth → deeper
classes → business logic/race conditions → verify → report → track),
backed by 14 reference files, each grounded in real disclosed reports
with actual payloads:

| Reference file | Covers |
|---|---|
| `ai-threat-awareness.md` | What a real AI-orchestrated attack campaign means for legitimate hunters |
| `google-dorking-patterns.md` | Search-engine-only recon, zero target interaction |
| `choosing-programs.md` | Picking a program worth your time |
| `low-hanging-fruit.md` | Subdomain takeover, open redirect, CORS, clickjacking |
| `rate-limit-bypass-patterns.md` | Missing rate limits, IP-rotation bypass |
| `mobile-api-patterns.md` | APK/IPA analysis, deep links, mobile API gaps |
| `idor-bola-patterns.md` | IDOR / broken access control (the #1 paying class) |
| `auth-jwt-patterns.md` | JWT bypass, session/password-reset/MFA logic |
| `xss-csrf-patterns.md` | XSS and CSRF |
| `ssrf-patterns.md` | Server-side request forgery |
| `sqli-rce-ssti-patterns.md` | SQL injection, template injection, RCE |
| `info-disclosure-patterns.md` | Leaked secrets and credentials |
| `business-logic-patterns.md` | Price/payment manipulation (highest ceiling — real $250k example) |
| `race-condition-patterns.md` | TOCTOU exploitation |

### `scripts/` — the tooling
| Script | Purpose |
|---|---|
| `generate_dorks.py` | Generates categorized Google-dorking queries for a target |
| `quickwin_scan.sh` | Automates subdomain-takeover, CORS, clickjacking, open-redirect discovery |
| `access_check.py` | Semi-automated IDOR/access-control sweep across sessions and IDs |
| `jwt_probe.py` | JWT tamper-variant generation for manual verification |
| `generate_report.py` | Turns a confirmed finding into a submission-ready report |
| `tracker.py` | CSV-backed tracker for programs and findings in progress |

See `scripts/README.md` for detailed usage of each.

### `install.sh` — legacy recon-tool installer
The original BBHT installer (dirsearch, Sublist3r, sqlmap, massdns,
SecLists, etc.). Predates the skill/scripts above and has some outdated
package references for modern distros — usable as a starting point for
classic recon tooling, but `setup.sh` is the one to run for this
toolkit's own scripts and skill.

## Using this on multiple machines / with a team

- **Personal machines**: `git clone` + `./setup.sh` on each one. The
  skill and scripts are entirely in-repo, so nothing else to sync.
- **Team use**: share this repo (or your fork/branch of it). Each
  team member's own program/finding tracking (`scripts/programs.csv`,
  `scripts/findings.csv`, `scripts/quickwin_results/`, any
  `target_config.json` with real session tokens) stays local and
  untracked via `.gitignore` — nobody's personal findings or live
  credentials get pushed to the shared repo by accident.
- Keep contributing back: new disclosed-report patterns, new scripts,
  and skill refinements belong in `.claude/skills/bug-hunting/` and
  `scripts/` respectively, same as everything already there.
