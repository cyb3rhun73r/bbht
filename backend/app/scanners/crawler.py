import asyncio
import re
from urllib.parse import urlparse, urljoin, parse_qs
import httpx

LINK_RE = re.compile(r'''(?:href|src|action)\s*=\s*["']([^"']+)["']''', re.I)
FORM_RE = re.compile(r'<form\b[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>', re.I | re.S)
INPUT_NAME_RE = re.compile(r'<input\b[^>]*name=["\']([^"\']+)["\']', re.I)

STATIC_EXT = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
    ".ttf", ".ico", ".mp4", ".webp", ".pdf", ".zip",
)


def _same_host(url: str, host: str) -> bool:
    try:
        return urlparse(url).netloc.split(":")[0] == host
    except Exception:
        return False


async def discover(base_url: str, client: httpx.AsyncClient, max_pages: int = 30) -> dict:
    """Crawl same-host pages starting at base_url and collect:
    - urls that already carry query parameters
    - GET-form action URLs combined with their input names (synthesized as query params)
    Returns {"parameterized_urls": [...], "pages_crawled": n}
    """
    parts = urlparse(base_url)
    host = parts.netloc.split(":")[0]
    scheme = parts.scheme or "https"
    root = f"{scheme}://{parts.netloc}"

    seen_pages: set[str] = set()
    found_urls: set[str] = set()
    queue = [base_url]

    # seed extra links from sitemap.xml if present
    try:
        r = await client.get(urljoin(root, "/sitemap.xml"), timeout=6)
        if r.status_code == 200 and "<urlset" in r.text[:500]:
            for loc in re.findall(r"<loc>(.*?)</loc>", r.text):
                if _same_host(loc, host):
                    queue.append(loc.strip())
    except Exception:
        pass

    while queue and len(seen_pages) < max_pages:
        url = queue.pop(0)
        if url in seen_pages:
            continue
        seen_pages.add(url)

        if parse_qs(urlparse(url).query):
            found_urls.add(url)

        try:
            r = await client.get(url, timeout=8, follow_redirects=True)
        except Exception:
            continue
        if "text/html" not in r.headers.get("content-type", ""):
            continue

        body = r.text

        for m in LINK_RE.finditer(body):
            link = m.group(1)
            if link.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            if link.lower().endswith(STATIC_EXT):
                continue
            abs_link = urljoin(url, link)
            if not _same_host(abs_link, host):
                continue
            if parse_qs(urlparse(abs_link).query):
                found_urls.add(abs_link)
            elif abs_link not in seen_pages and len(queue) + len(seen_pages) < max_pages * 3:
                queue.append(abs_link)

        for action, form_body in FORM_RE.findall(body):
            names = INPUT_NAME_RE.findall(form_body)
            if not names:
                continue
            action_url = urljoin(url, action or url)
            if not _same_host(action_url, host):
                continue
            synthetic_qs = "&".join(f"{n}=1" for n in names[:8])
            joiner = "&" if "?" in action_url else "?"
            found_urls.add(f"{action_url}{joiner}{synthetic_qs}")

    return {"parameterized_urls": sorted(found_urls), "pages_crawled": len(seen_pages)}
