# Information Disclosure / Secrets Exposure — Real Disclosed-Report Pattern Library

The easiest vulnerability class to find with pure automation — but still
needs manual judgment on impact (a leaked internal hostname is very
different from a leaked database password). Drawn from disclosed HackerOne
reports, almost all found via grepping JavaScript and public repos.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **API key hardcoded in JS source** | FetLife (H1 #1065041), Stripo (H1 #983331), Clario (H1 #1066410), Top Echelon (H1 #1051029) | Recurring pattern across many programs: Google/third-party API keys committed directly into shipped JavaScript bundles — trivially found by grepping any `.js` file served to the browser. |
| **Secrets in a public GitHub repo** | Starbucks (H1 #716292), X/xAI (H1 #674774), Rocket.Chat (H1 #766346) | JumpCloud API key, AppLovin key, Fabric/Google-services keys — all found hardcoded in a *public* GitHub repository, not even the app itself. Always check the org's public repos, not just the live site. |
| **Hardcoded crypto keys in a mobile/web bundle** | Reddit (H1 #2353237) | PayPal keys and other API/server secrets embedded directly in client-side code. |
| **Government API key leak** | GSA/api.data.gov (H1 #266449) | A valid, usable API key leaked from a government API portal — shows this pattern hits even security-mature orgs. |
| **Credential exposure via misconfigured endpoint** | DoD (H1 #1106505, Critical) | Full DB credentials (`DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`) exposed via an endpoint — often a debug/config endpoint left accessible in production. |

## Fast test approach
1. **Pull every JS file the target serves** (crawl with `katana`/`gau`, or just view-source + look at Network tab for bundled `.js`). Grep for: `api[_-]?key`, `secret`, `token`, `AKIA` (AWS key prefix), `-----BEGIN`, `password`, `Authorization`, service-specific key patterns (Google, Stripe, Twilio, SendGrid, etc.).
   - Tools: `gitleaks detect --source <dir>` or `trufflehog filesystem <dir>` against downloaded JS, or `trufflehog` directly against a git URL if source is exposed.
2. **Check the target org's public GitHub/GitLab repos** — not just the live site. Secrets leak into commit history even after being "removed" in a later commit; `trufflehog git <repo-url> --since-commit <old>` catches history, not just HEAD.
3. **Fuzz for exposed config/debug paths**: `.env`, `.git/config` (if exposed, the whole repo can sometimes be reconstructed), `config.json`, `/debug`, `/actuator` (Spring Boot), `/phpinfo.php`, backup files (`.bak`, `.old`, `~`), `docker-compose.yml`.
   - Tool: `ffuf -w wordlist.txt -u https://target/FUZZ` with a config/secrets-focused wordlist (SecLists has dedicated lists for this).
4. **Check error messages and stack traces**: force an error (malformed input, wrong content-type) and see if the response leaks internal paths, framework versions, DB connection strings, or stack traces.
5. **Check cloud storage exposure**: misconfigured S3/GCS buckets tied to the target — `s3scanner` or manual bucket-name guessing based on the org's naming conventions (`company-assets`, `company-backups`, `company-prod`, etc.).

## Triaging impact before reporting
Not all info disclosure is worth the same — be honest about severity:
- **High/Critical**: live credentials that grant access to something (DB password, cloud IAM key, admin API token) — especially if you can show the key actually *works* (without abusing it beyond confirming validity).
- **Medium**: internal hostnames/IPs, stack traces revealing framework/library versions, non-production secrets.
- **Low/Informational**: generic version banners, public-by-design info.

Confirm a leaked key is real and in-scope before reporting — test its
validity with the absolute minimum call needed to confirm (e.g. one
authenticated read-only API call), then stop; never use a discovered
credential to explore further than proving it's live and in-scope.
