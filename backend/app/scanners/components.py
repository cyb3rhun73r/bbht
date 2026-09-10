import re
import httpx

# regex -> (package name in the npm ecosystem, for OSV lookup)
LIB_PATTERNS = [
    (re.compile(r"jquery[-.](\d+\.\d+\.\d+)", re.I), "jquery"),
    (re.compile(r"bootstrap[-.](\d+\.\d+\.\d+)", re.I), "bootstrap"),
    (re.compile(r"angular(?:js)?[-.](\d+\.\d+\.\d+)", re.I), "angular"),
    (re.compile(r"react(?:-dom)?[-.@](\d+\.\d+\.\d+)", re.I), "react"),
    (re.compile(r"vue[-.](\d+\.\d+\.\d+)", re.I), "vue"),
    (re.compile(r"lodash[-.](\d+\.\d+\.\d+)", re.I), "lodash"),
    (re.compile(r"moment[-.](\d+\.\d+\.\d+)", re.I), "moment"),
    (re.compile(r"swiper[-.](\d+\.\d+\.\d+)", re.I), "swiper"),
    (re.compile(r"handlebars[-.](\d+\.\d+\.\d+)", re.I), "handlebars"),
]


async def _osv_query(client: httpx.AsyncClient, name: str, version: str) -> list[dict]:
    try:
        r = await client.post(
            "https://api.osv.dev/v1/query",
            json={"package": {"name": name, "ecosystem": "npm"}, "version": version},
            timeout=10,
        )
        if r.status_code == 200:
            return r.json().get("vulns", [])
    except Exception:
        pass
    return []


async def run(base_url: str, client: httpx.AsyncClient, emit):
    try:
        r = await client.get(base_url, timeout=10, follow_redirects=True)
    except Exception:
        return

    body = r.text
    found = {}
    for pattern, pkg in LIB_PATTERNS:
        m = pattern.search(body)
        if m:
            found[pkg] = m.group(1)

    for pkg, version in found.items():
        vulns = await _osv_query(client, pkg, version)
        if vulns:
            ids = ", ".join(v.get("id", "?") for v in vulns[:5])
            emit({
                "category": "A06:2021-Vulnerable and Outdated Components",
                "title": f"Outdated/vulnerable library: {pkg}@{version}",
                "severity": "high",
                "confidence": "confirmed",
                "location": base_url,
                "evidence": f"Detected {pkg} version {version} in page source, matched known advisories: {ids}",
                "poc": f"View page source of {base_url}, search for '{pkg}'",
                "remediation": f"Upgrade {pkg} to the latest patched version. See {ids} for details.",
            })
        else:
            emit({
                "category": "A06:2021-Vulnerable and Outdated Components",
                "title": f"Detected library version: {pkg}@{version}",
                "severity": "info",
                "confidence": "confirmed",
                "location": base_url,
                "evidence": f"Detected {pkg} version {version} in page source, no known OSV advisories at scan time",
                "poc": "",
                "remediation": "Keep third-party libraries up to date as a baseline practice.",
            })
