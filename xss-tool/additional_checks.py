#!/usr/bin/env python3
"""
Non-intrusive checks for Open Redirect, missing CSRF protection, and
improper-access-control hints, matching the "Non-Intrusive Submissions"
category most OpenBugBounty-style programs scope in alongside XSS.

Design constraints (same as xss_scanner.py):
  - Operates only on pages already fetched during the same bounded crawl
    (no additional brute-forcing of paths -- that would be exactly the
    "large-scale automated scanning" most programs prohibit).
  - Open redirect testing points the app at a safe, neutral external
    domain and only inspects the response; it never completes a real
    redirect chain to anything malicious.
  - CSRF and access-control checks are passive/observational: they flag
    what a human should manually verify, they don't attempt to forge or
    replay state-changing requests.
"""
import re
import time
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse

import requests
from bs4 import BeautifulSoup

REDIRECT_PARAM_NAMES = re.compile(
    r"^(url|redirect|redirect_uri|redirect_url|return|return_to|returnto|"
    r"next|dest|destination|continue|target|to|out|goto|link)$",
    re.IGNORECASE,
)
SAFE_EXTERNAL_TEST_HOST = "example.com"

CSRF_TOKEN_NAME_HINT = re.compile(r"csrf|token|authenticity|nonce|_token", re.IGNORECASE)

SENSITIVE_PATH_HINT = re.compile(
    r"/(admin|administration|backend|manage|dashboard|config|private|internal|debug)(/|$)",
    re.IGNORECASE,
)


@dataclass
class Finding:
    type: str
    url: str
    parameter: str
    payload: str
    confidence: str
    evidence: str
    notes: str = ""


def check_open_redirect(session: requests.Session, url: str, delay: float) -> list:
    findings = []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))

    for name, value in params.items():
        if not REDIRECT_PARAM_NAMES.match(name):
            continue

        test_params = dict(params)
        test_params[name] = f"https://{SAFE_EXTERNAL_TEST_HOST}/"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

        try:
            resp = session.get(test_url, timeout=10, allow_redirects=False)
        except requests.RequestException:
            continue
        time.sleep(delay)

        location = resp.headers.get("Location", "")
        if resp.status_code in (301, 302, 303, 307, 308) and SAFE_EXTERNAL_TEST_HOST in location:
            findings.append(Finding(
                type="Open Redirect",
                url=test_url,
                parameter=name,
                payload=f"https://{SAFE_EXTERNAL_TEST_HOST}/",
                confidence="High",
                evidence=f"HTTP {resp.status_code} redirects to attacker-controlled Location: {location}",
                notes="Verify manually that no allow-list/host validation is being bypassed via encoding tricks before submitting.",
            ))
        elif SAFE_EXTERNAL_TEST_HOST in resp.text[:2000]:
            findings.append(Finding(
                type="Possible client-side/meta redirect",
                url=test_url,
                parameter=name,
                payload=f"https://{SAFE_EXTERNAL_TEST_HOST}/",
                confidence="Low",
                evidence="Test host string appears early in response body (possible meta-refresh or JS redirect); needs manual confirmation in a browser.",
            ))
    return findings


def check_csrf_forms(page_url: str, html_text: str) -> list:
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")

    for form in soup.find_all("form"):
        method = (form.get("method") or "get").lower()
        if method != "post":
            continue  # CSRF is only meaningful for state-changing (POST) forms

        inputs = form.find_all("input")
        has_token = any(
            CSRF_TOKEN_NAME_HINT.search(i.get("name", "")) for i in inputs if i.get("name")
        )
        if has_token:
            continue

        action = urljoin(page_url, form.get("action") or page_url)
        field_names = [i.get("name") for i in inputs if i.get("name")]
        findings.append(Finding(
            type="Possible missing CSRF protection",
            url=action,
            parameter=",".join(field_names) or "(no named fields)",
            payload="n/a (static form analysis)",
            confidence="Low",
            evidence=f"POST form at {action} has no field matching common CSRF token naming patterns (csrf/token/authenticity/nonce).",
            notes="Static heuristic only. Verify the app doesn't rely on a header-based token (e.g. X-CSRF-Token via JS), SameSite cookies, or another mechanism not visible in static HTML before submitting.",
        ))
    return findings


def check_access_control_hints(page_url: str, html_text: str) -> list:
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")

    for a in soup.find_all("a", href=True):
        href = a["href"]
        if SENSITIVE_PATH_HINT.search(href):
            link = urljoin(page_url, href)
            findings.append(Finding(
                type="Sensitive-looking path linked without visible auth check",
                url=link,
                parameter="(link)",
                payload="n/a (observational only)",
                confidence="Low",
                evidence=f"Page {page_url} links to '{href}', which matches a sensitive-path naming pattern.",
                notes=(
                    "This is purely a naming-pattern hint from a page already crawled -- "
                    "no path brute-forcing was performed. Manually confirm (e.g. by "
                    "visiting while logged out, if you have a test account) whether "
                    "the linked resource actually enforces authorization before submitting."
                ),
            ))
    return findings
