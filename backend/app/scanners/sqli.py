import asyncio
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import httpx

ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "mysql_fetch",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "pg_query()", "postgresql", "ora-01756", "ora-00933",
    "sqlite3::", "sqlite_error", "microsoft odbc", "odbc sql server driver",
    "syntax error near", "unterminated string literal",
]

COMMON_PARAMS = ["id", "page", "search", "q", "user", "category", "item", "product", "pid", "uid"]

TRUE_PAYLOAD = "' OR '1'='1"
FALSE_PAYLOAD = "' AND '1'='2"
ERROR_PAYLOADS = ["'", "\"", "1' AND '1'='1", "1) OR (1=1", "' OR SLEEP(0)-- -"]


def _with_param(url: str, key: str, value: str) -> str:
    parts = urlparse(url)
    q = parse_qs(parts.query)
    q[key] = [value]
    return urlunparse(parts._replace(query=urlencode(q, doseq=True)))


async def _test_param(client: httpx.AsyncClient, url: str, key: str, emit):
    try:
        baseline = await client.get(url, timeout=8, follow_redirects=True)
    except Exception:
        return

    for payload in ERROR_PAYLOADS:
        try:
            r = await client.get(_with_param(url, key, payload), timeout=8, follow_redirects=True)
        except Exception:
            continue
        body_lower = r.text.lower()
        for sig in ERROR_SIGNATURES:
            if sig in body_lower and sig not in baseline.text.lower():
                emit({
                    "category": "A03:2021-Injection (SQL Injection)",
                    "title": f"Error-based SQL injection in parameter '{key}'",
                    "severity": "critical",
                    "confidence": "confirmed",
                    "location": url,
                    "evidence": f"Payload {payload!r} triggered DB error signature: '{sig}'",
                    "poc": _with_param(url, key, payload),
                    "remediation": "Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                })
                return

    try:
        r_true = await client.get(_with_param(url, key, TRUE_PAYLOAD), timeout=8, follow_redirects=True)
        r_false = await client.get(_with_param(url, key, FALSE_PAYLOAD), timeout=8, follow_redirects=True)
    except Exception:
        return

    len_base = len(baseline.text)
    len_true = len(r_true.text)
    len_false = len(r_false.text)
    if (
        r_true.status_code == 200
        and abs(len_true - len_base) < max(20, len_base * 0.02)
        and abs(len_true - len_false) > max(50, len_base * 0.05)
    ):
        emit({
            "category": "A03:2021-Injection (SQL Injection)",
            "title": f"Possible boolean-based blind SQL injection in parameter '{key}'",
            "severity": "high",
            "confidence": "likely",
            "location": url,
            "evidence": f"TRUE payload response length={len_true}, FALSE payload length={len_false}, baseline={len_base}",
            "poc": f"TRUE: {_with_param(url, key, TRUE_PAYLOAD)}  |  FALSE: {_with_param(url, key, FALSE_PAYLOAD)}",
            "remediation": "Use parameterized queries. Manually verify this finding as length-diffing can have false positives.",
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
