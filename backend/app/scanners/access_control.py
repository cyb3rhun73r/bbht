from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[key] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


async def run(base_url: str, client: httpx.AsyncClient, emit):
    parts = urlparse(base_url)
    q = parse_qs(parts.query)

    numeric_params = {k: v[0] for k, v in q.items() if v and v[0].isdigit()}
    if not numeric_params:
        return

    try:
        baseline = await client.get(base_url, timeout=8, follow_redirects=True)
    except Exception:
        return
    if baseline.status_code != 200:
        return

    for key, val in numeric_params.items():
        n = int(val)
        for candidate in {n - 1, n + 1}:
            if candidate < 0:
                continue
            test_url = _with_param(base_url, key, str(candidate))
            try:
                r = await client.get(test_url, timeout=8, follow_redirects=True)
            except Exception:
                continue
            if r.status_code == 200 and abs(len(r.text) - len(baseline.text)) > max(30, len(baseline.text) * 0.03):
                emit({
                    "category": "A01:2021-Broken Access Control (IDOR)",
                    "title": f"Possible IDOR via parameter '{key}'",
                    "severity": "high",
                    "confidence": "likely",
                    "location": base_url,
                    "evidence": (
                        f"Changing '{key}'={val} to {candidate} (no auth/ownership change) returned a "
                        f"different HTTP 200 response (baseline len={len(baseline.text)}, candidate len={len(r.text)})"
                    ),
                    "poc": test_url,
                    "remediation": (
                        "Enforce server-side object-level authorization checks (verify the requesting user "
                        "owns/may access the referenced object) rather than relying on obscurity of IDs."
                    ),
                })
