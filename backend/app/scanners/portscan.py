import asyncio
from urllib.parse import urlparse
import httpx

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    993: "IMAPS", 995: "POP3S", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch", 27017: "MongoDB",
}

RISKY = {21, 23, 3306, 3389, 5432, 6379, 9200, 27017, 445}


async def _check(host: str, port: int) -> bool:
    try:
        fut = asyncio.open_connection(host, port)
        reader, writer = await asyncio.wait_for(fut, timeout=2.5)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    except Exception:
        return False


async def run(base_url: str, client: httpx.AsyncClient, emit):
    host = urlparse(base_url).netloc.split(":")[0] or base_url

    sem = asyncio.Semaphore(30)

    async def handle(port, service):
        async with sem:
            open_ = await _check(host, port)
            if open_:
                severity = "medium" if port in RISKY else "info"
                emit({
                    "category": "A05:2021-Security Misconfiguration",
                    "title": f"Open port {port} ({service})",
                    "severity": severity,
                    "confidence": "confirmed",
                    "location": f"{host}:{port}",
                    "evidence": f"TCP connect succeeded on port {port}",
                    "poc": f"nc -zv {host} {port}",
                    "remediation": "Close unused ports or restrict via firewall/VPC to only what is required.",
                })

    await asyncio.gather(*(handle(p, s) for p, s in COMMON_PORTS.items()))
