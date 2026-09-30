# Access Control / IDOR / Auth Logic Toolkit

Semi-automated helpers for the vulnerability classes that don't fit a
regular scanner: broken access control, IDOR, and auth/session logic
flaws. These are currently the highest-paying, most in-demand bug classes
on HackerOne -- and the reason they pay well is that they require a human
to judge what "unauthorized" means for a given app. These scripts speed up
the repetitive part (replaying requests across sessions/IDs) and leave the
judgment part to you.

**Authorization:** only ever point these at assets explicitly in scope for
a bug bounty program you're enrolled in, or your own lab. Use only
accounts you control or are permitted to test with (e.g. two test
accounts you registered yourself). Every result these scripts flag is a
*candidate*, not a confirmed finding -- verify manually before reporting.

## Setup

```bash
pip install requests pyjwt
```

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

## Suggested workflow per target

1. Recon (subdomains, live hosts) with the rest of `bbht`.
2. Map the app manually once -- note every endpoint that takes an object
   ID or a privilege-sensitive action.
3. Create 2 test accounts, generate one resource per account.
4. Run `access_check.py` across those endpoints/IDs.
5. Run `jwt_probe.py` against any JWT you find.
6. Work `authz_checklist.md` by hand for business logic and auth flows.
7. Manually verify every flag before writing up a report.
