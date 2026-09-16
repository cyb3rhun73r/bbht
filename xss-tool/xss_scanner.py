#!/usr/bin/env python3
"""
Single-target XSS scanner for authorized bug bounty testing.

This scanner only ever operates on ONE target URL/domain that has already
passed scope_validator.py. It does not discover targets, does not scan
arbitrary hosts, and requires an explicit --confirm-authorized flag before
sending any payloads.

It performs:
  - Reflected XSS testing: injects marker payloads into URL query params
    and simple GET forms found on the page, then inspects whether/how the
    marker is reflected back unescaped.
  - DOM XSS heuristics: static-scans page/script source for dangerous sinks
    (innerHTML, document.write, eval, location.hash usage, etc.) and flags
    them as low-confidence, manual-verification-needed findings.

Each finding is assigned a confidence level (High / Medium / Low) based on
the reflection context, not just "reflected or not" -- this avoids false
positives from properly HTML-encoded output.
"""
import argparse
import html
import json
import re
import sys
import time
from dataclasses import dataclass, field, asdict
from urllib.parse import urljoin, urlparse, urlencode, parse_qsl, urlunparse

import requests
from bs4 import BeautifulSoup

from scope_validator import load_scope, check_scope

MARKER = "bbhtXss7f3q"
PAYLOADS = [
    f'"><script>/*{MARKER}*/</script>',
    f"'><img src=x onerror=/*{MARKER}*/>",
    f"<{MARKER}svg/onload=alert(1)>",
    f'"{MARKER}',
]

DOM_SINK_PATTERNS = [
    r"\.innerHTML\s*=",
    r"document\.write\s*\(",
    r"\beval\s*\(",
    r"location\.hash",
    r"location\.search",
    r"\.outerHTML\s*=",
    r"insertAdjacentHTML\s*\(",
]

DEFAULT_HEADERS = {
    "User-Agent": "bbht-xss-tool/1.0 (authorized-security-research)",
}


@dataclass
class Finding:
    type: str
    url: str
    parameter: str
    payload: str
    confidence: str
    evidence: str
    notes: str = ""


@dataclass
class ScanResult:
    target: str
    program: str
    pages_crawled: int
    findings: list = field(default_factory=list)


def crawl(session: requests.Session, base_url: str, max_pages: int, delay: float) -> list:
    """Same-origin breadth-first crawl, returns list of (url, html_text)."""
    origin = urlparse(base_url).netloc
    seen = set()
    queue = [base_url]
    pages = []

    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = session.get(url, timeout=10, headers=DEFAULT_HEADERS)
        except requests.RequestException:
            continue
        time.sleep(delay)
        if "text/html" not in resp.headers.get("Content-Type", ""):
            continue
        pages.append((url, resp.text))

        soup = BeautifulSoup(resp.text, "html.parser")
        for a in soup.find_all("a", href=True):
            link = urljoin(url, a["href"])
            if urlparse(link).netloc == origin and link not in seen:
                queue.append(link)

    return pages


def classify_reflection(html_text: str, marker_payload: str) -> tuple:
    """Return (confidence, evidence) describing how the payload was reflected."""
    if marker_payload in html_text:
        idx = html_text.find(marker_payload)
        context = html_text[max(0, idx - 40):idx + len(marker_payload) + 40]
        return "High", f"Payload reflected unescaped: ...{context}..."

    escaped = html.escape(marker_payload)
    if escaped in html_text:
        idx = html_text.find(escaped)
        context = html_text[max(0, idx - 40):idx + len(escaped) + 40]
        return "Low", f"Payload reflected but HTML-escaped (likely not exploitable): ...{context}..."

    if MARKER in html_text:
        idx = html_text.find(MARKER)
        context = html_text[max(0, idx - 40):idx + len(MARKER) + 40]
        return "Medium", f"Marker present but payload structure altered: ...{context}..."

    return None, None


def test_reflected_params(session: requests.Session, url: str, delay: float) -> list:
    findings = []
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    if not params:
        return findings

    for param in params:
        for payload in PAYLOADS:
            test_params = dict(params)
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            try:
                resp = session.get(test_url, timeout=10, headers=DEFAULT_HEADERS)
            except requests.RequestException:
                continue
            time.sleep(delay)

            confidence, evidence = classify_reflection(resp.text, payload)
            if confidence:
                findings.append(Finding(
                    type="Reflected XSS",
                    url=test_url,
                    parameter=param,
                    payload=payload,
                    confidence=confidence,
                    evidence=evidence,
                ))
                break  # one confirmed finding per param is enough
    return findings


def test_forms(session: requests.Session, page_url: str, html_text: str, delay: float) -> list:
    findings = []
    soup = BeautifulSoup(html_text, "html.parser")

    for form in soup.find_all("form"):
        action = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "get").lower()
        if method != "get":
            continue  # only test safe, idempotent GET forms

        inputs = form.find_all(["input", "textarea"])
        field_names = [i.get("name") for i in inputs if i.get("name")]
        if not field_names:
            continue

        for payload in PAYLOADS:
            data = {name: payload for name in field_names}
            test_url = urlunparse(urlparse(action)._replace(query=urlencode(data)))
            try:
                resp = session.get(test_url, timeout=10, headers=DEFAULT_HEADERS)
            except requests.RequestException:
                continue
            time.sleep(delay)

            confidence, evidence = classify_reflection(resp.text, payload)
            if confidence:
                findings.append(Finding(
                    type="Reflected XSS (form)",
                    url=test_url,
                    parameter=",".join(field_names),
                    payload=payload,
                    confidence=confidence,
                    evidence=evidence,
                    notes=f"Form action={action}",
                ))
                break
    return findings


def test_dom_sinks(page_url: str, html_text: str) -> list:
    findings = []
    for pattern in DOM_SINK_PATTERNS:
        for match in re.finditer(pattern, html_text):
            idx = match.start()
            context = html_text[max(0, idx - 40):idx + 60]
            findings.append(Finding(
                type="Potential DOM XSS sink",
                url=page_url,
                parameter="(client-side)",
                payload="n/a (static analysis)",
                confidence="Low",
                evidence=f"Sink pattern '{pattern}' found: ...{context}...",
                notes="Static heuristic only. Requires manual verification with a real browser/PoC.",
            ))
    return findings


def scan(target: str, scope_path: str, max_pages: int, delay: float, confirm_authorized: bool) -> ScanResult:
    scope = load_scope(scope_path)
    result = check_scope(target, scope)
    if not result.in_scope:
        print(f"[ABORT] {target} is not in scope: {result.reason}", file=sys.stderr)
        sys.exit(1)

    if not confirm_authorized:
        print(
            "[ABORT] Scope check passed, but you must pass --confirm-authorized to "
            "attest that you are personally registered/authorized for this program "
            "and accept its testing rules before any requests are sent.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"[OK] Scope check passed: {result.reason}")
    print(f"[*] Starting authorized single-target scan of {target}")

    session = requests.Session()
    pages = crawl(session, target, max_pages, delay)
    print(f"[*] Crawled {len(pages)} page(s) within target origin")

    all_findings = []
    for url, html_text in pages:
        all_findings.extend(test_reflected_params(session, url, delay))
        all_findings.extend(test_forms(session, url, html_text, delay))
        all_findings.extend(test_dom_sinks(url, html_text))

    return ScanResult(
        target=target,
        program=scope.get("program", "unknown"),
        pages_crawled=len(pages),
        findings=[asdict(f) for f in all_findings],
    )


def main():
    parser = argparse.ArgumentParser(description="Authorized single-target XSS scanner (scope-gated).")
    parser.add_argument("--scope", required=True, help="Path to scope JSON file")
    parser.add_argument("--target", required=True, help="Single target URL to scan (must pass scope check)")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl (default 25)")
    parser.add_argument("--delay", type=float, default=0.5, help="Delay between requests in seconds (default 0.5)")
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Required: attest you are authorized to test this specific target under the program's rules",
    )
    parser.add_argument("--out", default="scan_result.json", help="Output JSON path")
    args = parser.parse_args()

    result = scan(args.target, args.scope, args.max_pages, args.delay, args.confirm_authorized)

    with open(args.out, "w") as f:
        json.dump(asdict(result), f, indent=2)

    print(f"[*] {len(result.findings)} finding(s) written to {args.out}")


if __name__ == "__main__":
    main()
