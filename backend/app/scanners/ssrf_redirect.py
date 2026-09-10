from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "dest", "destination", "continue", "target"]
SSRF_PARAMS = ["url", "uri", "path", "dest", "redirect", "feed", "callback", "webhook", "proxy", "endpoint"]

CANARY_DOMAIN = "https://example.com/bbht-canary"
SSRF_PAYLOADS = ["http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80", "http://localhost"]


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[key] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


async def run(base_url: str, client: httpx.AsyncClient, emit):
    parts = urlparse(base_url)
    existing = set(parse_qs(parts.query).keys())
    candidates = existing & set(REDIRECT_PARAMS + SSRF_PARAMS) or set(REDIRECT_PARAMS)

    for key in candidates:
        test_url = _with_param(base_url, key, CANARY_DOMAIN)
        try:
            r = await client.get(test_url, timeout=8, follow_redirects=False)
        except Exception:
            continue
        location = r.headers.get("location", "")
        if r.status_code in (301, 302, 303, 307, 308) and "example.com" in location:
            emit({
                "category": "A01:2021-Broken Access Control (Open Redirect)",
                "title": f"Open redirect via parameter '{key}'",
                "severity": "medium",
                "confidence": "confirmed",
                "location": base_url,
                "evidence": f"HTTP {r.status_code} redirected to attacker-controlled '{location}'",
                "poc": test_url,
                "remediation": "Validate redirect targets against an allowlist of internal paths/domains instead of trusting user input.",
            })

    for key in (existing & set(SSRF_PARAMS)):
        for payload in SSRF_PAYLOADS:
            test_url = _with_param(base_url, key, payload)
            try:
                r = await client.get(test_url, timeout=6, follow_redirects=True)
            except Exception:
                continue
            body_lower = r.text.lower()
            if any(sig in body_lower for sig in ["ami-id", "instance-id", "root:x:0:0", "connection refused to"]):
                emit({
                    "category": "A10:2021-Server-Side Request Forgery (SSRF)",
                    "title": f"Possible SSRF via parameter '{key}'",
                    "severity": "critical",
                    "confidence": "likely",
                    "location": base_url,
                    "evidence": f"Payload '{payload}' produced a response containing internal-service markers",
                    "poc": test_url,
                    "remediation": "Validate/allowlist outbound destinations server-side; block requests to link-local and loopback ranges.",
                })
                break
