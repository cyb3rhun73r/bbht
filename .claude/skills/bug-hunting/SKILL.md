---
name: bug-hunting
description: Methodology and tooling for hunting web/API bugs on authorized bug bounty programs (HackerOne, Bugcrowd, Intigriti) or your own lab. Covers fast low-hanging-fruit checks (subdomain takeover, open redirect, CORS misconfiguration, clickjacking) plus Broken Access Control, IDOR/BOLA, and auth/session logic flaws (the highest-paying, most in-demand classes on HackerOne), and pattern libraries for XSS, CSRF, SSRF, SQL injection, SSTI, RCE, and information/secrets disclosure — all grounded in real disclosed HackerOne reports with exact payloads used, not generic OWASP text. Use this whenever the user wants to test an in-scope target for any of these bug classes, wants an easy/fast first finding, plan a hunting session against a bounty program, interpret results from access_check.py or jwt_probe.py, or wants a recommended test order for a new target. Also use it when the user mentions bug bounty hunting, IDOR, BOLA, broken access control, subdomain takeover, open redirect, CORS, clickjacking, rate limiting, brute force, mobile app testing, APK analysis, Google dorking, Google hacking, search-engine recon, XSS, CSRF, SSRF, SQL injection, SSTI, RCE, information disclosure, JWT/session bypass testing, or picking/choosing a bug bounty program, even if they don't name this skill directly. It does NOT cover building generic exploit/attack frameworks, and every test it guides must be run only against targets the user is explicitly authorized to test.
---

# Bug Hunting: Real-World Vulnerability Pattern Library

## Why this skill exists
Generic OWASP checklists tell you *what* a vulnerability class is. This
skill tells you *where disclosed reports actually found each one* — which
endpoint types, which parameters, which frameworks — pulled from real
HackerOne disclosures, so testing time goes to the highest-yield spots
first instead of guessing. It leans hardest on Broken Access Control and
IDOR because those are currently the #1 most exploited, fastest-rising
bounty category on HackerOne (IAC payouts up 134% YoY per HackerOne's 2025
report) and the one generic scanners can't find at all — they require
understanding what the app's workflow is *supposed* to allow. The other
reference files (XSS/CSRF, SSRF, SQLi/SSTI/RCE, info disclosure) cover the
rest of what disclosed reports show pays well, with real examples to
calibrate against.

## Hard rule
Only test targets the user has explicit authorization for (an enrolled
bug bounty program's in-scope assets, or their own lab/CTF). Only use
test accounts they control or are permitted to test with. If this isn't
clearly established, ask before proceeding — don't assume authorization
from context.

## 0. No target yet? Start with program selection
If the user hasn't picked a program, **read `references/choosing-programs.md`
first** — which program to hunt matters as much as which bugs to look
for. It covers what makes a program beginner-friendly (wide scope, pays
for Low/Medium severity, fast triage, newer/less-hunted), red flags to
avoid, and a practical first-week plan using `scripts/tracker.py`.

## Workflow

### 1. Scope and recon (if not already done)
Confirm the target domain/app is in scope. If recon hasn't been run yet,
point the user at the recon scripts elsewhere in this repo (subdomain
enum, live-host probing, nuclei) to map the attack surface first — this
skill picks up once there's a concrete app/API to test.

### 1a. Google dorking pass (do this before anything that touches the target directly)
**Read `references/google-dorking-patterns.md` first of all.** This is
the only check in the whole skill that needs zero interaction with the
target — just search-engine queries. Real disclosed examples (Khan
Academy, Mars/Banfield) were found exactly this way — an unauthenticated
endpoint or enumerable URL pattern that a search engine had already
indexed. Zero setup cost, so there's no reason to skip it.

Run `scripts/generate_dorks.py <domain>` to get the full categorized
query list (secrets/config, admin panels, enumerable action endpoints,
exposed documents, error pages, subdomain discovery). **Then actually run
each query yourself using your own web-search tool** (not the user's
browser) and review the results — don't just hand the user a query list
and stop. Summarize anything that looks like a real hit (an indexed
admin panel, a config file, a URL matching the join/unsubscribe/reset/
invite pattern) and flag it as a candidate for the user to verify is
in-scope before they interact with it further. Querying a search engine
this way is normal search-API usage, not scraping, so it's fine to do
directly — just never scrape Google's results pages or automate around
its Terms of Service, and never visit/interact with a flagged URL
yourself without the user confirming scope first.

### 1b. Low-hanging fruit pass (do this first among active checks, especially on a new target or for a first paid report)
**Read `references/low-hanging-fruit.md` now.** Subdomain takeover, open
redirect, CORS misconfiguration, and clickjacking are fast to check
(minutes, not hours), need no custom payload development, and many
programs still pay for them. This is the highest-value use of the first
30-45 minutes on any new target — especially if the user needs a result
soon. Run `scripts/quickwin_scan.sh <domain>` to automate the discovery
part of this pass (subdomain takeover sweep, CORS check, clickjacking
header check, open-redirect param discovery) — it outputs candidates,
which still need manual confirmation per that reference file. Only move
to the deeper workflow below once this pass is done.

Also check `references/rate-limit-bypass-patterns.md` at this stage —
missing/bypassable rate limiting on login, OTP, and password-reset
endpoints is nearly as fast to check as the low-hanging-fruit classes
above and pays well (a disclosed $12,000 2FA-bypass example is in there).

If the target has a mobile app in scope, **read
`references/mobile-api-patterns.md`** — mobile apps are consistently
under-tested relative to web apps on the same program (higher setup cost
= less competition for the same scope), and findings there are often
rated higher severity than their web equivalent.

### 2. Map the app and pick test candidates
Walk the app manually (or review a captured traffic log/HAR) and list
every endpoint that either:
- takes an object ID (invoice, order, ticket, document, user profile...), or
- performs a privileged or state-changing action.

**Read `references/idor-bola-patterns.md` now** — it ranks where IDOR/BOLA
bugs are actually found in disclosed reports (export endpoints, billing,
GraphQL mutations, bulk endpoints, post-state-change actions) so the user
tests the highest-yield spots first instead of guessing. Action-level BOLA
(delete/modify/trigger on someone else's object) is the single largest
category in the data and the one hunters most often skip — don't only
test whether data can be *read*, test whether it can be *changed*.

If the target uses GraphQL, check `__schema` introspection first (often
left enabled) and treat opaque Global IDs as base64-decodable — the
reference file has the decode/swap/re-encode pattern.

### 3. Run the semi-automated checks
- **Access control / IDOR:** set up `scripts/access_check.py` with 2+ test
  accounts and the endpoints from step 2 (see that script's own docstring
  and `scripts/example_config.json`). It sweeps IDs across sessions and
  flags likely cross-account access. Every flag is a *candidate* —
  confirm manually.
- **JWT / token auth:** if the app uses JWTs, capture one from the user's
  own session and run `scripts/jwt_probe.py`. Read
  `references/auth-jwt-patterns.md` first — it maps each tamper technique
  the script generates (alg=none, alg confusion, weak secret, stripped
  signature) to a real disclosed report so the user knows what a
  successful bypass actually looks like and isn't chasing a dead end.
- **Session/password-reset/MFA logic:** no script substitutes for this.
  Use the checklist in `references/auth-jwt-patterns.md` (reset token
  reuse, race conditions across OTP/reset steps, MFA-skip by direct URL)
  together with `scripts/authz_checklist.md`'s full manual checklist.

### 3b. Other vulnerability classes (once access-control/auth pass is done)
These have their own reference files with real disclosed examples and a
"fast test approach" section each — read the relevant one before testing
that class so effort goes to where disclosed reports actually find bugs,
not a generic sweep:
- **XSS / CSRF** → `references/xss-csrf-patterns.md`
- **SSRF** → `references/ssrf-patterns.md`
- **SQL injection / SSTI / RCE** → `references/sqli-rce-ssti-patterns.md`
- **Information disclosure / leaked secrets** → `references/info-disclosure-patterns.md`

Rough prioritization if time is limited: info disclosure and SSRF are the
fastest to sweep and still pay well; XSS is high-volume but low per-bug
value now; SQLi/SSTI/RCE are rarer finds but pay the most per bug when
confirmed — don't center a time-boxed session on them alone.

### 4. Verify before reporting
Nothing from step 3 is a finding until manually confirmed:
- Reproduce twice, from a clean session (no leftover cookies/state).
- Capture the exact request/response showing the unauthorized data/action.
- State impact plainly: what was exposed/changed, to whom, what an
  attacker could actually do with it.

`scripts/authz_checklist.md` section 6 has the report-writeup structure.
Once confirmed, run `scripts/generate_report.py` to turn your notes into
a clean, submission-ready writeup (title, severity, steps, PoC request/
response, impact, remediation) instead of formatting it from scratch —
it prompts interactively or takes a JSON file (see its docstring).

### 5. Track it
Log the program (`scripts/tracker.py program add`) and the finding
(`scripts/tracker.py finding add`) as you go, and update status
(`finding update --id <n> --status submitted`) as it moves through
triage. `scripts/tracker.py summary` gives a quick pipeline/payout view
once the user is running more than one program at a time — useful for
seeing which programs and vuln classes are actually converting.

## Reference files
- `references/google-dorking-patterns.md` — search-engine-only recon
  (Khan Academy's `site:` class enumeration, Mars/Banfield's unauthenticated
  unsubscribe endpoint found via search), dork operator cheat sheet. Zero
  interaction with the target — do this before anything else.
- `references/choosing-programs.md` — how to pick a beginner-friendly
  program (scope, payout policy, triage speed), red flags, first-week plan.
- `references/low-hanging-fruit.md` — subdomain takeover, open redirect,
  CORS misconfig, clickjacking, and other fast/easy checks with exact
  disclosed payloads (Tumblr, Zomato, GlassWire, Twitter Periscope,
  etc.) — start here on a new target.
- `references/rate-limit-bypass-patterns.md` — missing rate limits and
  bypass techniques (IP-rotation headers, race conditions) with disclosed
  examples (MTN Group, Mail.ru, a $12k 2FA bypass) and impact-math guidance
  for the report.
- `references/mobile-api-patterns.md` — APK/IPA static analysis, deep
  link hijacking, insecure local storage, mobile-vs-web API gaps, with
  disclosed examples (8x8, GlassWire, Reverb.com).
- `references/idor-bola-patterns.md` — BOLA taxonomy from a 2026 empirical
  study of 84+ disclosed reports, plus specific disclosed examples
  (Shopify, HackerOne's own program, DoD, etc.) and where to look first.
- `references/auth-jwt-patterns.md` — JWT bypass techniques and
  session/password-reset/MFA logic flaws, each tied to a disclosed report
  so the user can calibrate what "found" looks like.
- `references/xss-csrf-patterns.md` — disclosed XSS/CSRF examples
  (Expedia, Shopify, Bumble, Zendesk, etc.) and fast test approaches.
- `references/ssrf-patterns.md` — disclosed SSRF examples (GitLab,
  Shopify, Snapchat's DNS-rebinding bypass, etc.), OOB detection workflow.
- `references/sqli-rce-ssti-patterns.md` — disclosed SQLi (Mail.ru, DoD),
  SSTI→RCE (Uber's $10k Jinja2 finding, Shopify, Fastify), and general RCE
  examples, with escalation and safety notes.
- `references/info-disclosure-patterns.md` — disclosed secrets-leak
  examples (FetLife, Starbucks, Reddit, GSA) and how to triage severity.

## Related scripts (same repo, `scripts/`)
- `generate_dorks.py <domain>` — generates the categorized Google-dorking
  query list for a target. Run the queries with your own web-search tool
  (not by having the user paste them into a browser) and review hits.
- `quickwin_scan.sh <domain>` — automates the low-hanging-fruit discovery
  pass (subdomain takeover sweep, CORS check, clickjacking header check,
  open-redirect param discovery). Outputs candidates for manual
  confirmation into a timestamped results directory.
- `access_check.py` — replays requests across sessions/ID ranges, flags
  likely IDOR/access-control violations for manual review.
- `jwt_probe.py` — generates JWT tamper variants for manual verification.
- `generate_report.py` — turns confirmed-finding notes into a clean,
  submission-ready report (interactive or from a JSON file).
- `tracker.py` — local CSV-backed tracker for programs and
  findings-in-progress (`program add/list`, `finding add/update/list`,
  `summary`).
- `authz_checklist.md` — full manual checklist for business logic, auth
  flows, and cases no script can safely flag.
- `example_config.json` / `README.md` — setup for the scripts above.

## What this skill won't do
It won't help build a generic exploitation framework, write self-spreading
or destructive payloads, or test targets without confirmed authorization.
If asked for any of that, decline and redirect to the scoped workflow
above.
