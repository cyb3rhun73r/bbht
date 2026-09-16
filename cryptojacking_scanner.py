#!/usr/bin/env python3
"""
cryptojacking_scanner.py

Scans a website's HTML and linked JavaScript for signs of browser-based
cryptojacking (unauthorized in-browser cryptocurrency miners injected via
compromised plugins, ads, or CDN files) -- e.g. the Coinhive/CoinImp/
Crypto-Loot style attacks.

This is a detection tool only. It never mines, connects to mining pools,
or executes any script it finds -- it just fetches text and pattern-matches.

Usage:
    python3 cryptojacking_scanner.py https://example.com
    python3 cryptojacking_scanner.py -f urls.txt -o report.json
"""

import argparse
import json
import re
import sys
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    sys.exit("This tool requires the 'requests' package: pip install requests")

USER_AGENT = "Mozilla/5.0 (compatible; CryptojackingScanner/1.0; +security-research)"
TIMEOUT = 10
MAX_JS_FILES = 25

# Known miner script filenames / library signatures seen in real
# cryptojacking incidents.
KNOWN_MINER_FILES = [
    "coinhive.min.js",
    "coinhive.js",
    "cnhv.js",
    "authedmine.min.js",
    "crypto-loot.js",
    "cryptoloot.js",
    "webminepool.js",
    "coinimp.js",
    "coin-have.js",
    "jsecoin.js",
    "minero.cc",
    "deepminer.js",
    "webmine.cz",
    "coinnebula.js",
    "cryptonight.js",
    "webassemblyminer.js",
]

# Known mining-pool / stratum-proxy domains that in-browser miners
# connect to over WebSocket.
KNOWN_MINER_DOMAINS = [
    "coinhive.com",
    "authedmine.com",
    "coin-hive.com",
    "cnhv.co",
    "crypto-loot.com",
    "webminepool.com",
    "coinimp.com",
    "www.coinimp.com",
    "webmine.pro",
    "webmine.cz",
    "minero.cc",
    "monerise.com",
    "coinnebula.com",
    "papoto.com",
    "projectpoi.com",
    "listat.biz",
    "moneropool.com",
    "webxmr.com",
    "deepminer.tk",
]

# Code-level signatures: object/API names + suspicious constructs that
# in-browser Monero miners characteristically use.
CODE_SIGNATURES = [
    (r"CoinHive\.(Anonymous|User|Token)", "CoinHive JS API usage"),
    (r"CRLT\.Anonymous", "Crypto-Loot JS API usage"),
    (r"new\s+CoinImp", "CoinImp miner instantiation"),
    (r"JSECoin\s*\(", "JSEcoin miner call"),
    (r"deepMiner", "DeepMiner API usage"),
    (r"webminepool", "WebMinePool API usage"),
    (r"startMining\s*\(", "generic startMining() call"),
    (r"wasmJsonInterface|cryptonight_wasm|cryptonight\.wasm", "CryptoNight WebAssembly miner"),
    (r"stratum\+tcp://", "raw stratum mining-pool URI"),
    (r"throttleMiner|setThrottle\s*\(", "miner CPU throttle control (common evasion tactic)"),
]

HEX_ENTITY_RE = re.compile(r"&#x?[0-9a-fA-F]+;?")


def fetch(url, session):
    try:
        resp = session.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        resp.raise_for_status()
        return resp.text
    except requests.RequestException as e:
        return None


def extract_script_srcs(html, base_url):
    srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE)
    return [urllib.parse.urljoin(base_url, s) for s in srcs]


def decode_obfuscation_hint(text):
    """Return True if the text looks heavily obfuscated (common for
    injected malicious payloads hiding inside otherwise legit files)."""
    if len(text) < 200:
        return False
    hex_hits = len(HEX_ENTITY_RE.findall(text))
    eval_hits = len(re.findall(r"\beval\s*\(", text))
    fromcharcode_hits = len(re.findall(r"String\.fromCharCode", text))
    return hex_hits > 20 or eval_hits > 3 or fromcharcode_hits > 3


def scan_text(text, source_label):
    findings = []

    for fname in KNOWN_MINER_FILES:
        if fname.lower() in text.lower():
            findings.append({
                "type": "known_miner_filename",
                "detail": fname,
                "source": source_label,
            })

    for domain in KNOWN_MINER_DOMAINS:
        if domain.lower() in text.lower():
            findings.append({
                "type": "known_miner_domain",
                "detail": domain,
                "source": source_label,
            })

    for pattern, desc in CODE_SIGNATURES:
        if re.search(pattern, text):
            findings.append({
                "type": "code_signature",
                "detail": desc,
                "source": source_label,
            })

    if decode_obfuscation_hint(text):
        findings.append({
            "type": "obfuscation_heuristic",
            "detail": "heavy eval()/fromCharCode()/hex-entity usage -- inconclusive on its own, review manually",
            "source": source_label,
        })

    return findings


def scan_url(url, session):
    result = {"url": url, "findings": [], "js_files_checked": 0, "error": None}

    html = fetch(url, session)
    if html is None:
        result["error"] = "failed to fetch page"
        return result

    result["findings"].extend(scan_text(html, url))

    script_urls = extract_script_srcs(html, url)[:MAX_JS_FILES]
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(fetch, js_url, session): js_url for js_url in script_urls}
        for fut in as_completed(futures):
            js_url = futures[fut]
            js_text = fut.result()
            if js_text is None:
                continue
            result["js_files_checked"] += 1
            result["findings"].extend(scan_text(js_text, js_url))

    return result


def main():
    parser = argparse.ArgumentParser(
        description="Detect browser-based cryptojacking (unauthorized in-page "
                     "cryptocurrency miners) on websites you are authorized to test."
    )
    parser.add_argument("urls", nargs="*", help="URL(s) to scan")
    parser.add_argument("-f", "--file", help="file with one URL per line")
    parser.add_argument("-o", "--output", help="write JSON report to this file")
    args = parser.parse_args()

    targets = list(args.urls)
    if args.file:
        with open(args.file) as fh:
            targets.extend(line.strip() for line in fh if line.strip())

    if not targets:
        parser.error("provide at least one URL, via argument or -f/--file")

    targets = [t if t.startswith(("http://", "https://")) else "https://" + t for t in targets]

    session = requests.Session()
    all_results = []

    for url in targets:
        print(f"[*] Scanning {url} ...")
        res = scan_url(url, session)
        all_results.append(res)

        if res["error"]:
            print(f"    [!] {res['error']}")
            continue

        if not res["findings"]:
            print(f"    [+] No cryptojacking indicators found ({res['js_files_checked']} scripts checked)")
        else:
            print(f"    [!] {len(res['findings'])} indicator(s) found ({res['js_files_checked']} scripts checked):")
            for f in res["findings"]:
                print(f"        - [{f['type']}] {f['detail']}  (source: {f['source']})")

    if args.output:
        with open(args.output, "w") as fh:
            json.dump(all_results, fh, indent=2)
        print(f"\n[*] Report written to {args.output}")


if __name__ == "__main__":
    main()
