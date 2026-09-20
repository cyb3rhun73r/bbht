"""PortSwigger Web Security Academy 'collector' (§5).

Deliberately does not scrape portswigger.net live: their site's automated-
access terms aren't something this tool should route around, and the cheat
sheets change wording/formatting often enough that a scraper would need
constant maintenance to stay accurate anyway. Instead, the curated seed set
in data/payloads/*.json captures the canonical payloads from the pages
listed below, each with a source_url pointing at the exact page.

To refresh the seed set by hand: open the page, diff its current payload
list against data/payloads/<category>.json, and update entries - keeping
the original payload text and updating source metadata (§29/§30).
"""

REFERENCE_PAGES = {
    "xss": "https://portswigger.net/web-security/cross-site-scripting/cheat-sheet",
    "xss-contexts": "https://portswigger.net/web-security/cross-site-scripting/contexts",
    "sqli": "https://portswigger.net/web-security/sql-injection/cheat-sheet",
    "sqli-union": "https://portswigger.net/web-security/sql-injection/union-attacks",
    "ssrf": "https://portswigger.net/web-security/ssrf",
    "ssrf-url-validation-bypass": "https://portswigger.net/web-security/ssrf/url-validation-bypass-cheat-sheet",
    "ssti": "https://portswigger.net/web-security/server-side-template-injection",
    "xxe": "https://portswigger.net/web-security/xxe",
    "csrf": "https://portswigger.net/web-security/csrf",
    "nosqli": "https://portswigger.net/web-security/nosql-injection",
    "cors": "https://portswigger.net/web-security/cors",
    "prototype-pollution": "https://portswigger.net/web-security/prototype-pollution",
    "path-traversal": "https://portswigger.net/web-security/file-path-traversal",
    "web-cache-deception": "https://portswigger.net/web-security/web-cache-deception",
}


def reference_pages():
    return dict(REFERENCE_PAGES)
