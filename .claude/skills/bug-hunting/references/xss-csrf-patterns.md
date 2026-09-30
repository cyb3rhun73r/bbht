# XSS & CSRF — Real Disclosed-Report Pattern Library

Drawn from disclosed HackerOne reports (found via `site:hackerone.com/reports`
searches). XSS is the single most-reported bug on HackerOne, but per-bug
payouts are falling as it gets commoditized — treat it as volume/practice,
not your primary income target. CSRF is rarer now (frameworks default to
protecting against it) but pays disproportionately well when found, because
it usually means a *complete* control failure, not just a missing header.

## XSS — where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Reflected via header, not just params** | GSA/data.gov (H1 #265528) | Reflected XSS with WAF + Chrome XSS-Auditor bypass — don't stop at the first blocked payload, try encoding variants. |
| **Reflected via uncommon param** | Expedia (H1 #1420529) | Found via `origCity` — a booking-flow parameter, not an obvious search box. Map *every* param, not just the visible search field. |
| **Cache poisoning → stored XSS** | Expedia (H1 #1760213) | A cookie parameter reflected into a page that got cached meant one poisoned response served the payload to every subsequent visitor — turns a "low" reflected bug into stored-XSS-at-scale impact. |
| **Stored XSS via shareable links** | Shopify/Linkpop (H1 #1441988, $1,600) | Stored payload in an admin-facing dashboard field, delivered through a link the victim (an admin) was induced to click — impact came from *who* views it, not just that it's stored. |
| **Worse-impact stored vs reflected** | Slack (H1 #258198) | Same payload class, but because it was stored and hit more users automatically, it paid more — always note whether a reflected finding could instead be stored somewhere (profile fields, comments, filenames). |

### Fast test approach
1. Crawl the app (or use `gau`/`katana` from the recon toolkit) to enumerate every parameter across every endpoint — not just the search box.
2. Inject a distinct marker per param, escalating if blocked:
```
"><svg onload=alert(document.domain)>
"><img src=x onerror=alert(document.domain)>
'-alert(document.domain)-'
javascript:alert(document.domain)          -- for href/src-sink contexts
%22%3E%3Csvg%20onload=alert(1)%3E           -- URL-encoded
&quot;&gt;&lt;svg onload=alert(1)&gt;         -- HTML-entity encoded, for double-decode contexts
```
3. Check reflection not just in HTML body — also in `<script>` blocks, HTML attributes, JSON responses later rendered client-side, and HTTP response headers echoed into the page.
4. For anything client-controlled that later gets cached (CDN, reverse proxy), check if your payload persists across a second unauthenticated request — that's cache-poisoned stored XSS, a much bigger finding.
5. Tools: `dalfox` (`dalfox pipe` fed from `gau`), or manual with Burp Repeater.

## CSRF — where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Security-question/password-change CSRF** | DoD (H1 #670924, #410099) | "Change security question" and "change password" endpoints missing CSRF tokens — direct account takeover, no XSS needed. |
| **Social-account linking CSRF** | Bumble (H1 #127703) | CSRF on the "link your Google/Facebook account" flow let an attacker link *their own* social account to the victim's account, then log in as the victim via that social login — account takeover without ever touching the victim's password. |
| **Unconfirmed-email signup CSRF** | Khan Academy (H1 #419891) | `/signup/email` endpoint vulnerable to CSRF, letting an attacker claim/take over accounts tied to unconfirmed email addresses. |
| **CSRF via job/async endpoint** | Zendesk (H1 #102194, Critical) | CSRF on `<subdomain>.zendesk.com/jobs/createjob`, reached via the *bulk user import* feature (`/import?kind=user`) — not a normal form submit, which is exactly why most testers would skip it. **Exact technique:** the bulk-import flow uploads a CSV, then submits a request like `jobs/createjob?[password_email_change_csv_import]=true&job[token]=<csv_upload_id>&job[update_records]=true&type=user_import`. The *only* "protection" on this request was `job[token]`, which wasn't a real anti-CSRF token — it was just the ID of the already-uploaded CSV, generated at upload time and not tied to the session in a way that blocked cross-site submission. Because the import can update existing user records (`update_records=true`), an attacker-crafted auto-submitting form pointing a victim's browser at this endpoint could alter their account data/password-email without any real CSRF token check. **Lesson:** don't assume a `token` param in a request means CSRF protection — verify it's actually session-bound and unpredictable, not just an opaque ID for unrelated purposes (here, a file-upload reference). |
| **OAuth-linkage CSRF** | Periscope/X (H1 #235642, Critical) | CSRF in the OAuth linkage between two platforms — check any "connect your account to X" flow specifically for a `state` parameter and whether it's validated. |

### Fast test approach
1. List every **state-changing** request (not just obvious forms): change password, change security question, change email, link/unlink social account, delete resource, change privacy settings, async job triggers.
2. For each, check: is there a CSRF token? Is it tied to the session (not a static/global token)? Is it actually validated server-side (remove it / reuse an old one / use a token from a different session and see if the request still succeeds)?
3. Check `SameSite` cookie attribute — `SameSite=Lax` or unset is more exploitable than `Strict`.
4. For OAuth/social-linking flows specifically: check the `state` parameter is present, unpredictable, and actually validated on callback — this is a recurring high-value CSRF pattern (Bumble, Periscope examples above).
5. Build a minimal auto-submitting HTML PoC (a form with `onload` auto-submit) for anything flagged — programs want to see it actually works, not just "no token present."
