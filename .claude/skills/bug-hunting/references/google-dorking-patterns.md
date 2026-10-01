# Google Dorking / Search-Engine-Discoverable Vulnerabilities

The purest "low-hanging fruit" class there is: these bugs are found
**entirely through a search engine query** — no scanner, no proxy, no
payload sent to the target at all. You're not probing the app; you're
reading what Google (or Bing/DuckDuckGo) already crawled and indexed.
This makes it the single lowest-setup-cost bug class in this skill — a
browser tab is the whole toolchain — which is exactly why it's worth a
pass on every new target before anything else.

## Why this works
Search engines crawl and cache whatever they can reach, including pages
a site never meant to be public or indexed (no `robots.txt` block, no
`noindex` meta tag, or a crawler has already cached a page the site later
tried to remove — crawled content persists in the index for a while after
removal). The vulnerability isn't the search engine; it's that something
sensitive was reachable and indexable in the first place.

## Real disclosed examples

| Finding | Report | Exact technique |
|---|---|---|
| **Enumerate every "join class" link via one dork** | Khan Academy (H1 #1210043, High severity) | The dork `site:khanacademy.org/join/*` returned every indexed class-join URL. Each one let an attacker join someone else's class without an invite — a direct consequence of class-join pages being both unauthenticated-joinable *and* indexable. Khan Academy's fix was blocking the crawler via `robots.txt`/`noindex`, but cached results stayed visible in Google for a while after the fix — worth re-checking a target's fix with a fresh search days later. |
| **Find an unauthenticated unsubscribe endpoint via site-search** | Mars/Banfield (H1 #2055081) | A plain `site:` search on the target domain surfaced an unsubscribe endpoint URL that required no authentication/authorization — submitting any user's email to it unsubscribed them from all company emails, no login needed. The endpoint was never meant to be discoverable or directly linkable, but nothing stopped Google from indexing and surfacing it. |
| **Indexed internal/third-party links leaking PII** | HackerOne's own disclosed-reports pages (H1 #1256371, disputed/Low) | A link found via search, when an extra parameter was appended, revealed a researcher's address/phone number on a *third-party* page the link pointed to. HackerOne ruled this out of their own scope (third-party site's issue), but the underlying lesson holds broadly: disclosed/public report pages and their embedded links are themselves a dorking target — crawl what other researchers' public writeups link to, not just the target's own domain. |

## Dork cheat sheet — operators and ready-to-use queries

Core operators:
```
site:target.com              -- restrict to the target domain
inurl:keyword                -- keyword appears in the URL
intitle:keyword              -- keyword appears in the page title
filetype:ext  (or ext:ext)   -- restrict to a file extension
intext:keyword               -- keyword appears in the page body
-keyword                     -- exclude results containing keyword
"exact phrase"                -- exact match
*                             -- wildcard (any path segment/word)
```

**Exposed config / secrets files:**
```
site:target.com ext:env | ext:yaml | ext:yml | ext:json | ext:xml
site:target.com filetype:sql "INSERT INTO" "VALUES"
site:target.com filetype:log intext:password
site:target.com inurl:config intext:"DB_PASSWORD" OR intext:"api_key"
site:target.com filetype:env "DB_PASSWORD"
```

**Exposed admin/login panels:**
```
site:target.com inurl:admin intitle:"login"
site:target.com inurl:(wp-admin | phpmyadmin | adminer)
```

**Enumerable/unauthenticated functional endpoints (the Khan Academy / Mars pattern):**
```
site:target.com inurl:join
site:target.com inurl:unsubscribe
site:target.com inurl:invite
site:target.com inurl:reset
site:target.com inurl:token
```
Generalize this: any dork that surfaces a URL pattern containing an action
verb (join/invite/reset/unsubscribe/confirm/approve/download) is worth
testing manually — load it unauthenticated and see what happens.

**Exposed documents / internal files:**
```
site:target.com filetype:pdf | filetype:xlsx | filetype:docx intext:confidential
site:target.com inurl:drive.google.com OR inurl:docs.google.com
```
(Google Drive/Docs links shared "anyone with the link" sometimes get
indexed if linked from a public page — check sharing settings implications,
not just content, when you find one: an editable doc is a bigger finding
than a read-only one.)

**Exposed error pages / stack traces (confirms a framework/version, sometimes leaks paths):**
```
site:target.com intext:"stack trace" OR intext:"fatal error" OR intext:"warning: mysql"
```

**Cached/removed content (checking if a "fixed" bug is really gone):**
Use Google's cache link (where still offered) or the Wayback Machine
(`web.archive.org/web/*/target.com/*`) to see whether a page the target
removed or blocked from crawling is still retrievable — this is how you'd
verify the Khan Academy-style "fixed via robots.txt but still cached"
situation, and it can itself be worth reporting if sensitive cached data
is still retrievable after the "fix."

## Fast test approach
1. Run the config/secrets dorks against the target domain first — zero
   risk, pure search.
2. Run the action-verb/endpoint dorks (`inurl:join`, `inurl:unsubscribe`,
   etc.) and manually test each surfaced URL unauthenticated — this is
   where the real disclosed examples above actually paid out.
3. Check `web.archive.org` for the target domain for anything previously
   indexed that may still be retrievable even if the live site has since
   fixed/removed it.
4. Cross-reference with `info-disclosure-patterns.md` once you find
   something — the triage/severity guidance there (is this credential
   actually live? is this PII real?) applies the same way here.
5. Automate the sweep with a dork-list tool if testing many
   targets/programs: `GoogleDorker` or similar scripts can batch a dork
   list against a domain, but manual review of each hit still matters —
   these tools surface search results, they don't confirm impact.

## A note on scope and terms of service
Dorking itself only queries a public search engine — it doesn't touch the
target's infrastructure directly, which is part of why it's such low-risk
recon. But whatever you *find* and then access (an admin panel, an
unsubscribe endpoint, a leaked file) is still subject to the same
authorization rules as everything else in this skill: confirm the asset
is in the program's scope before interacting with it, and stop at
confirming impact — don't pull more data than needed to prove the finding.
