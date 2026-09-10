import asyncio
import socket
from urllib.parse import urlparse
import httpx


async def _resolve(host: str) -> bool:
    try:
        await asyncio.get_event_loop().run_in_executor(None, socket.gethostbyname, host)
        return True
    except Exception:
        return False


async def _probe(client: httpx.AsyncClient, host: str) -> dict | None:
    for scheme in ("https", "http"):
        try:
            r = await client.get(f"{scheme}://{host}", timeout=6, follow_redirects=True)
            title = ""
            if "text/html" in r.headers.get("content-type", ""):
                start = r.text.lower().find("<title>")
                if start != -1:
                    end = r.text.lower().find("</title>", start)
                    title = r.text[start + 7:end].strip()[:120] if end != -1 else ""
            return {
                "scheme": scheme,
                "status": r.status_code,
                "server": r.headers.get("server", ""),
                "title": title,
            }
        except Exception:
            continue
    return None


async def run(base_url: str, client: httpx.AsyncClient, emit):
    domain = urlparse(base_url).netloc or base_url
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]

    names = {domain}
    try:
        r = await client.get(
            f"https://crt.sh/?q=%25.{domain}&output=json", timeout=20
        )
        if r.status_code == 200 and r.text.strip():
            for entry in r.json():
                for n in entry.get("name_value", "").splitlines():
                    n = n.strip().lstrip("*.").lower()
                    if n.endswith(domain):
                        names.add(n)
    except Exception:
        pass

    names = list(names)[:150]  # keep scans bounded
    sem = asyncio.Semaphore(20)

    async def handle(host):
        async with sem:
            alive = await _resolve(host)
            if not alive:
                return
            info = await _probe(client, host)
            if info:
                emit({
                    "category": "Recon",
                    "title": f"Live host: {host}",
                    "severity": "info",
                    "confidence": "confirmed",
                    "location": f"{info['scheme']}://{host}",
                    "evidence": f"HTTP {info['status']} | server={info['server']} | title={info['title']}",
                    "poc": "",
                    "remediation": "",
                })

    await asyncio.gather(*(handle(h) for h in names))
