import asyncio
import secrets
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

COMMON_PARAMS = ["q", "search", "query", "name", "comment", "message", "text", "input", "keyword"]


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[key] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


async def _test_param(client: httpx.AsyncClient, url: str, key: str, emit):
    marker = "bbht" + secrets.token_hex(4)
    payload = f"<script>/*{marker}*/alert('{marker}')</script>"
    target = _with_param(url, key, payload)
    try:
        r = await client.get(target, timeout=8, follow_redirects=True)
    except Exception:
        return

    if "text/html" not in r.headers.get("content-type", ""):
        return

    if payload in r.text:
        emit({
            "category": "A03:2021-Injection (Cross-Site Scripting)",
            "title": f"Reflected XSS in parameter '{key}'",
            "severity": "high",
            "confidence": "confirmed",
            "location": url,
            "evidence": f"Payload reflected unescaped in HTML response body: {payload}",
            "poc": target,
            "remediation": "HTML-encode all user input before rendering (context-aware output encoding) and set a strict Content-Security-Policy.",
        })
    elif marker in r.text and "&lt;script&gt;" not in r.text:
        # Reflected without full tag but not clearly encoded either - flag as likely, needs manual check
        emit({
            "category": "A03:2021-Injection (Cross-Site Scripting)",
            "title": f"Possible reflected XSS in parameter '{key}' (needs manual verification)",
            "severity": "medium",
            "confidence": "likely",
            "location": url,
            "evidence": f"Marker '{marker}' reflected in response but full payload structure unclear",
            "poc": target,
            "remediation": "Manually verify reflection context; HTML-encode all user input before rendering.",
        })


async def run(base_url: str, client: httpx.AsyncClient, emit):
    parts = urlparse(base_url)
    existing_params = list(parse_qs(parts.query).keys())
    params_to_test = existing_params or COMMON_PARAMS

    sem = asyncio.Semaphore(5)

    async def handle(key):
        async with sem:
            await _test_param(client, base_url, key, emit)

    await asyncio.gather(*(handle(k) for k in params_to_test))
