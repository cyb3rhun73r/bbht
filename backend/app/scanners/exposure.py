import asyncio
import httpx

# path -> (signature substrings to confirm it's real content, not a custom 404 page)
SENSITIVE_PATHS = {
    "/.env": ["APP_KEY", "DB_PASSWORD", "SECRET", "="],
    "/.git/HEAD": ["ref:"],
    "/.git/config": ["[core]", "repositoryformatversion"],
    "/.aws/credentials": ["aws_access_key_id"],
    "/wp-config.php.bak": ["DB_PASSWORD", "wpdb"],
    "/config.php.bak": ["<?php"],
    "/.DS_Store": ["Bud1"],
    "/backup.zip": ["PK"],
    "/backup.sql": ["INSERT INTO", "CREATE TABLE"],
    "/server-status": ["Apache Server Status"],
    "/actuator/env": ["propertySources"],
    "/actuator/health": ["\"status\""],
    "/phpinfo.php": ["phpinfo()", "PHP Version"],
    "/.well-known/security.txt": ["Contact:"],
    "/swagger.json": ["\"swagger\"", "\"openapi\""],
    "/api/swagger.json": ["\"swagger\"", "\"openapi\""],
    "/id_rsa": ["PRIVATE KEY"],
    "/debug": ["debug"],
    "/.htpasswd": [":"],
}


async def run(base_url: str, client: httpx.AsyncClient, emit):
    base_url = base_url.rstrip("/")
    sem = asyncio.Semaphore(15)

    async def handle(path, sigs):
        async with sem:
            try:
                r = await client.get(base_url + path, timeout=8, follow_redirects=False)
            except Exception:
                return
            if r.status_code != 200:
                return
            body = r.text
            if not any(s.lower() in body.lower() for s in sigs):
                return
            severity = "high"
            if path in ("/server-status", "/actuator/health", "/.well-known/security.txt", "/debug"):
                severity = "low"
            emit({
                "category": "A02:2021-Cryptographic Failures / Sensitive Data Exposure",
                "title": f"Sensitive file exposed: {path}",
                "severity": severity,
                "confidence": "confirmed",
                "location": base_url + path,
                "evidence": body[:300],
                "poc": f"curl {base_url}{path}",
                "remediation": f"Remove or restrict public access to '{path}'. Never deploy secrets or backups into the webroot.",
            })

    await asyncio.gather(*(handle(p, s) for p, s in SENSITIVE_PATHS.items()))
