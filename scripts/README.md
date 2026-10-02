# Bug Hunting Toolkit

Scripts supporting the `.claude/skills/bug-hunting/` skill: fast
low-hanging-fruit scanning, semi-automated IDOR/access-control/auth
testing for the classes that don't fit a regular scanner, report
generation, and a lightweight program/finding tracker.

**Authorization:** only ever point these at assets explicitly in scope for
a bug bounty program you're enrolled in, or your own lab. Use only
accounts you control or are permitted to test with (e.g. two test
accounts you registered yourself). Every result these scripts flag is a
*candidate*, not a confirmed finding -- verify manually before reporting.

## Setup

```bash
pip install requests pyjwt
# quickwin_scan.sh also benefits from (optional but recommended):
#   subfinder, httpx, dnsx, subzy, gau or katana -- see bbht/install.sh
```

## 0. quickwin_scan.sh -- automated low-hanging-fruit discovery

```bash
./quickwin_scan.sh target.com
```

Sweeps subdomains for takeover candidates, checks every live host for CORS
misconfiguration and clickjacking header issues, and collects URLs with
redirect-like parameters for manual open-redirect testing. Outputs
candidates to a timestamped results directory -- see
`.claude/skills/bug-hunting/references/low-hanging-fruit.md` for how to
confirm each one and build a PoC.

## 1. access_check.py -- IDOR / broken access control

1. Copy `example_config.json` to `target_config.json`.
2. Fill in:
   - `base_url`: the in-scope target
   - `sessions`: auth headers/cookies for 2+ accounts you control, plus
     an `anon` entry for unauthenticated requests
   - `owned_ids`: which object IDs belong to which account (create test
     data with each account first, e.g. create an invoice as userA, note
     its ID)
   - `templates`: the endpoints to test, with `{id}` as a placeholder
   - `id_range`: every ID to sweep across (include both accounts' IDs)
3. Run:
   ```bash
   python3 access_check.py --config target_config.json --out results.json
   ```
4. Review flagged rows (`CROSS_ACCOUNT_ACCESS`, `UNAUTH_ACCESS`) by hand --
   re-request manually and confirm the response actually contains the
   other account's real data before treating it as a bug.

## 2. jwt_probe.py -- JWT / token-based auth bypass checks

```bash
python3 jwt_probe.py --token "eyJhbGciOi..."
```

Capture a token from your own authenticated session (browser devtools /
Burp). The script prints tampered variants (alg=none, stripped signature,
weak-secret guesses, alg-confusion, privilege-claim flips) -- you then
send the ones that apply yourself (curl/Repeater) and check whether the
server actually accepts them. It never sends anything itself.

## 3. authz_checklist.md -- manual testing checklist

Everything a script can't safely flag: business logic, multi-step
workflow bypass, password reset token strength, MFA bypass, rate
limiting, session fixation, etc. Work through this on every target after
running the scripts above.

## 4. generate_report.py -- report writeup generator

```bash
python3 generate_report.py                              # interactive
python3 generate_report.py --from-json finding.json --out report.md
```

Once you've confirmed a finding, this formats it into a clean,
submission-ready report (title, severity, steps to reproduce, PoC
request/response, impact, remediation). It does not decide whether you
have a real bug -- that's still your judgment call.

## 5. tracker.py -- program and finding tracker

```bash
python3 tracker.py program add --name "Acme" --platform hackerone --url https://hackerone.com/acme --scope "*.acme.com"
python3 tracker.py finding add --program "Acme" --target api.acme.com --vuln-class IDOR --status testing
python3 tracker.py finding update --id 1 --status submitted
python3 tracker.py finding list --status testing
python3 tracker.py summary
```

CSV-backed (`programs.csv`, `findings.csv` in the working directory) so
it's also easy to open in a spreadsheet. Useful once you're running more
than one program in parallel.

## Suggested workflow per target

1. Pick a program -- see
   `.claude/skills/bug-hunting/references/choosing-programs.md`. Track it
   with `tracker.py program add`.
2. Recon (subdomains, live hosts) with the rest of `bbht`.
3. Run `quickwin_scan.sh` and work through the low-hanging-fruit reference
   file for a fast first result.
4. Map the app manually once -- note every endpoint that takes an object
   ID or a privilege-sensitive action.
5. Create 2 test accounts, generate one resource per account.
6. Run `access_check.py` across those endpoints/IDs.
7. Run `jwt_probe.py` against any JWT you find.
8. Work `authz_checklist.md` by hand for business logic and auth flows.
9. Manually verify every flag before writing up a report with
   `generate_report.py`, and log it with `tracker.py finding add/update`.
