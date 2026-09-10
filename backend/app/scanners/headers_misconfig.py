import httpx

SECURITY_HEADERS = {
    "strict-transport-security": (
        "medium", "Missing Strict-Transport-Security",
        "Set 'Strict-Transport-Security: max-age=63072000; includeSubDomains; preload' to enforce HTTPS.",
    ),
    "x-content-type-options": (
        "low", "Missing X-Content-Type-Options",
        "Set 'X-Content-Type-Options: nosniff' to prevent MIME sniffing.",
    ),
    "x-frame-options": (
        "medium", "Missing X-Frame-Options / frame-ancestors CSP",
        "Set 'X-Frame-Options: DENY' or a CSP frame-ancestors directive to prevent clickjacking.",
    ),
    "content-security-policy": (
        "medium", "Missing Content-Security-Policy",
        "Define a restrictive CSP to mitigate XSS and data-injection attacks.",
    ),
    "referrer-policy": (
        "low", "Missing Referrer-Policy",
        "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
    ),
    "permissions-policy": (
        "low", "Missing Permissions-Policy",
        "Restrict powerful browser features via Permissions-Policy.",
    ),
}


async def run(base_url: str, client: httpx.AsyncClient, emit):
    try:
        r = await client.get(base_url, timeout=10, follow_redirects=True)
    except Exception:
        return

    headers_lower = {k.lower(): v for k, v in r.headers.items()}

    for h, (sev, title, remediation) in SECURITY_HEADERS.items():
        if h not in headers_lower:
            emit({
                "category": "A05:2021-Security Misconfiguration",
                "title": title,
                "severity": sev,
                "confidence": "confirmed",
                "location": base_url,
                "evidence": f"Response headers did not include '{h}'",
                "poc": f"curl -I {base_url}",
                "remediation": remediation,
            })

    server = headers_lower.get("server", "")
    powered_by = headers_lower.get("x-powered-by", "")
    if server or powered_by:
        emit({
            "category": "A05:2021-Security Misconfiguration",
            "title": "Server/technology banner disclosure",
            "severity": "info",
            "confidence": "confirmed",
            "location": base_url,
            "evidence": f"Server='{server}' X-Powered-By='{powered_by}'",
            "poc": f"curl -I {base_url}",
            "remediation": "Suppress or generalize Server/X-Powered-By headers to reduce fingerprinting.",
        })

    # Cookie flags
    set_cookies = r.headers.get("set-cookie")
    if set_cookies:
        cookies = set_cookies if isinstance(set_cookies, list) else [set_cookies]
        for c in cookies:
            missing = []
            if "secure" not in c.lower():
                missing.append("Secure")
            if "httponly" not in c.lower():
                missing.append("HttpOnly")
            if "samesite" not in c.lower():
                missing.append("SameSite")
            if missing:
                emit({
                    "category": "A07:2021-Identification and Authentication Failures",
                    "title": f"Cookie missing {', '.join(missing)} flag(s)",
                    "severity": "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                    "confidence": "confirmed",
                    "location": base_url,
                    "evidence": c[:200],
                    "poc": f"curl -I {base_url}",
                    "remediation": "Set Secure, HttpOnly and SameSite=Lax/Strict on all session cookies.",
                })

    # HTTP TRACE method check
    try:
        r2 = await client.request("TRACE", base_url, timeout=8)
        if r2.status_code < 400:
            emit({
                "category": "A05:2021-Security Misconfiguration",
                "title": "HTTP TRACE method enabled",
                "severity": "low",
                "confidence": "confirmed",
                "location": base_url,
                "evidence": f"TRACE returned HTTP {r2.status_code}",
                "poc": f"curl -X TRACE {base_url}",
                "remediation": "Disable the TRACE/TRACK HTTP methods on the web server.",
            })
    except Exception:
        pass

    # Directory listing heuristic
    if "index of /" in r.text.lower()[:2000]:
        emit({
            "category": "A05:2021-Security Misconfiguration",
            "title": "Directory listing enabled",
            "severity": "medium",
            "confidence": "confirmed",
            "location": base_url,
            "evidence": "Response body contains 'Index of /' directory listing markers",
            "poc": f"curl {base_url}",
            "remediation": "Disable autoindex/directory listing on the web server.",
        })
