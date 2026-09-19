#!/usr/bin/env python3
"""
Bug Hunt HQ - Smart Recon & Attack-Surface Triage (desktop GUI)

Authorized security testing only. This tool performs active HTTP requests
against a target you specify. Do not point it at anything you do not have
explicit written permission to test.

Build into a Windows .exe with PyInstaller (see build.bat / README.md).
"""

import json
import os
import queue
import random
import re
import shlex
import shutil
import string
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from tkinter import filedialog, messagebox, ttk
from urllib.parse import urljoin, urlparse, parse_qs, urlsplit

try:
    import requests
except ImportError:
    print("Missing dependency 'requests'. Run: pip install -r requirements.txt")
    sys.exit(1)

APP_NAME = "Bug Hunt HQ"
DATA_DIR = os.path.join(os.path.expanduser("~"), ".bughunthq")
os.makedirs(DATA_DIR, exist_ok=True)

USER_AGENT = "BugHuntHQ/1.0 (authorized-security-testing)"
DEFAULT_HEADERS = {"User-Agent": USER_AGENT}

# ----------------------------------------------------------------------------
# Rule engine: recon signal -> suggested attack class -> tool command template
# ----------------------------------------------------------------------------

SQLI_PARAM_HINTS = {"id", "uid", "user", "user_id", "product_id", "cat", "category",
                     "search", "q", "query", "sort", "order", "filter", "item", "pid", "ref"}
LFI_PARAM_HINTS = {"file", "path", "page", "doc", "document", "template", "include",
                    "folder", "dir", "load", "view", "download"}
REDIRECT_PARAM_HINTS = {"redirect", "redirect_uri", "redirect_url", "url", "next",
                         "return", "returnurl", "return_url", "continue", "dest",
                         "destination", "goto", "target"}
SSRF_PARAM_HINTS = {"url", "uri", "link", "src", "source", "callback", "webhook",
                     "feed", "image", "fetch", "proxy", "path"}
CMDI_PARAM_HINTS = {"cmd", "exec", "command", "run", "ping", "host", "ip", "shell"}
UPLOAD_PATH_HINTS = {"upload", "file", "media", "attachment", "import"}
ADMIN_PATH_HINTS = {"admin", "manage", "dashboard", "internal", "cpanel", "wp-admin"}
JWT_RE = re.compile(r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")

# OWASP Top 10 (2021) category labels, used to tag every suggestion.
OWASP = {
    "A01": "A01 Broken Access Control",
    "A02": "A02 Cryptographic Failures",
    "A03": "A03 Injection",
    "A04": "A04 Insecure Design",
    "A05": "A05 Security Misconfiguration",
    "A06": "A06 Vulnerable & Outdated Components",
    "A07": "A07 Identification & Authentication Failures",
    "A08": "A08 Software & Data Integrity Failures",
    "A09": "A09 Security Logging & Monitoring Failures",
    "A10": "A10 Server-Side Request Forgery",
}

# OWASP API Security Top 10 (2023) - the current, API-specific companion list.
# Applied alongside OWASP (web) Top 10 codes where a finding is API-shaped.
OWASP_API = {
    "API1": "API1:2023 Broken Object Level Authorization",
    "API2": "API2:2023 Broken Authentication",
    "API3": "API3:2023 Broken Object Property Level Authorization",
    "API4": "API4:2023 Unrestricted Resource Consumption",
    "API5": "API5:2023 Broken Function Level Authorization",
    "API6": "API6:2023 Unrestricted Access to Sensitive Business Flows",
    "API7": "API7:2023 Server Side Request Forgery",
    "API8": "API8:2023 Security Misconfiguration",
    "API9": "API9:2023 Improper Inventory Management",
    "API10": "API10:2023 Unsafe Consumption of APIs",
}

# MITRE ATT&CK (Enterprise) technique the finding maps to once exploited -
# gives every suggestion a tactic/technique, not just an OWASP category.
MITRE = {
    "T1190": "T1190 Exploit Public-Facing Application (Initial Access)",
    "T1595.002": "T1595.002 Active Scanning: Vulnerability Scanning (Reconnaissance)",
    "T1592.002": "T1592.002 Gather Victim Host Information: Software (Reconnaissance)",
    "T1213": "T1213 Data from Information Repositories (Collection)",
    "T1213.003": "T1213.003 Data from Information Repositories: Code Repositories (Collection)",
    "T1588.006": "T1588.006 Obtain Capabilities: Vulnerabilities (Resource Development)",
    "T1552.001": "T1552.001 Unsecured Credentials: Credentials In Files (Credential Access)",
    "T1552.005": "T1552.005 Unsecured Credentials: Cloud Instance Metadata API (Credential Access)",
    "T1539": "T1539 Steal Web Session Cookie (Credential Access)",
    "T1606": "T1606 Forge Web Credentials (Credential Access)",
    "T1078": "T1078 Valid Accounts (Initial Access/Persistence/Privilege Escalation)",
    "T1204.001": "T1204.001 User Execution: Malicious Link (Execution)",
    "T1505.003": "T1505.003 Server Software Component: Web Shell (Persistence)",
    "T1530": "T1530 Data from Cloud Storage (Collection)",
}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TOOL_HINTS = {
    # A03 Injection
    "sqlmap": "sqlmap -u \"{url}\" --batch --level=2 --risk=1",
    "dalfox": "dalfox url \"{url}\"",
    "commix": "commix --url \"{url}\" --batch",
    # A01 Broken Access Control
    "ffuf-lfi": "ffuf -u \"{url_marker}\" -w wordlists/lfi.txt -mc all",
    "ffuf-dir": "ffuf -u \"{base}/FUZZ\" -w wordlists/common.txt -mc 200,301,302,403",
    "corsy": "corsy -u \"{url}\"",
    # A02 Cryptographic Failures
    "tlsx": "tlsx -u \"{host}\" -json -so",
    # A05 Security Misconfiguration / A06 Vulnerable & Outdated Components
    "nuclei": "nuclei -u \"{url}\" -tags {tags}",
    "wpscan": "wpscan --url \"{base}\" --enumerate vp,vt,u",
    "git-dumper": "git-dumper \"{base}/.git\" ./loot/{host}-git",
    "trivy": "trivy fs ./loot/{host}-git",
    "graphql-introspect": "curl -s -X POST \"{url}\" -H \"Content-Type: application/json\" "
                           "-d \"{{\\\"query\\\":\\\"{{__schema{{types{{name}}}}}}\\\"}}\"",
    # A07 Identification & Authentication Failures
    "jwt_tool": "jwt_tool \"{token}\" -M at",
    # A10 Server-Side Request Forgery
    "interactsh-client": "interactsh-client",
}

# Pure-Python tools vendored as source (no separate runtime needed) rather
# than a compiled binary. Path is relative to the bundled tools/ directory.
PY_SCRIPT_TOOLS = {
    "sqlmap": os.path.join("sqlmap", "sqlmap.py"),
    "git-dumper": os.path.join("git-dumper", "git_dumper.py"),
    "commix": os.path.join("commix", "commix.py"),
    "jwt_tool": os.path.join("jwt_tool", "jwt_tool.py"),
    "corsy": os.path.join("corsy", "corsy.py"),
}

# Compiled binaries tools/fetch_tools.py fetches - kept in sync with that
# script's GO_TOOLS keys, used here only to report Setup-tab status.
GO_TOOL_NAMES = ["nuclei", "subfinder", "ffuf", "dalfox", "tlsx", "trivy", "interactsh-client"]


def bundled_tools_dir():
    """Where fetch_tools.py vendors tools, and where the running app looks for them."""
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, "tools")


def child_env():
    """Environment for any subprocess this app spawns. Forces UTF-8 I/O so a
    vendored tool that prints Unicode (banners, box-drawing, non-ASCII
    findings) doesn't crash on Windows, where a piped child process would
    otherwise fall back to the system codepage (cp1252 etc) and raise
    UnicodeEncodeError the moment it prints something outside that codepage."""
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    return env


def find_tool_path(tool_name):
    """Look for a bundled compiled binary first, then fall back to PATH."""
    exe_name = tool_name + (".exe" if os.name == "nt" else "")
    candidate = os.path.join(bundled_tools_dir(), exe_name)
    if os.path.isfile(candidate):
        return candidate
    return shutil.which(tool_name)


def resolve_tool_argv(tool_name, rest_args):
    """Build a runnable argv for a suggested tool: bundled binary > bundled
    Python script (run in-process via this app's own interpreter, even when
    frozen into an exe) > whatever's on PATH. Returns None if nothing works."""
    path = find_tool_path(tool_name)
    if path:
        return [path] + rest_args
    if tool_name in PY_SCRIPT_TOOLS:
        script_path = os.path.join(bundled_tools_dir(), PY_SCRIPT_TOOLS[tool_name])
        if os.path.isfile(script_path):
            if getattr(sys, "frozen", False):
                return [sys.executable, "--bhq-pyscript", script_path] + rest_args
            return [sys.executable, script_path] + rest_args
    return None


def marker():
    return "bhq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


# ----------------------------------------------------------------------------
# MITRE ATT&CK dataset (fetched/indexed by tools/fetch_attack_data.py). When
# present, this replaces the hand-typed MITRE dict as the source of truth for
# technique names/tactics and lets the app flag any code that doesn't exist
# in the official data. When absent, everything still works off the
# hand-typed fallback - this is an enhancement, not a hard dependency.
# ----------------------------------------------------------------------------

_attack_index_cache = None
_attack_webapp_cache = None


def load_attack_index():
    global _attack_index_cache
    if _attack_index_cache is not None:
        return _attack_index_cache
    path = os.path.join(bundled_tools_dir(), "attack-data", "enterprise-attack-index.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        _attack_index_cache = data
    except Exception:
        _attack_index_cache = False
    return _attack_index_cache


def load_attack_webapp_subset():
    global _attack_webapp_cache
    if _attack_webapp_cache is not None:
        return _attack_webapp_cache
    path = os.path.join(bundled_tools_dir(), "attack-data", "webapp-relevant.json")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        _attack_webapp_cache = data
    except Exception:
        _attack_webapp_cache = False
    return _attack_webapp_cache


def mitre_lookup(code):
    """Resolve a bare technique ID like 'T1190' to a display label, preferring
    the live ATT&CK dataset over the hand-typed MITRE fallback dict."""
    if not code:
        return ""
    idx = load_attack_index()
    if idx and code in idx.get("techniques", {}):
        rec = idx["techniques"][code]
        tactics = "/".join(rec["tactics_display"]) if rec["tactics_display"] else ""
        return "{} {}{}".format(code, rec["name"], " ({})".format(tactics) if tactics else "")
    return MITRE.get(code, code)


def validate_mitre_codes(log_cb):
    """Cross-check every technique ID this app's suggestion engine uses
    against the live dataset, if loaded. Reports anything that no longer
    resolves (renamed/deprecated upstream) instead of silently mislabeling."""
    idx = load_attack_index()
    if not idx:
        log_cb("[*] No local MITRE ATT&CK dataset found - using built-in technique labels. "
               "Run tools\\fetch_attack_data.py to fetch/validate against the live dataset.")
        return
    known = idx.get("techniques", {})
    bad = [c for c in MITRE if c not in known]
    log_cb("[*] MITRE ATT&CK dataset loaded (v{}, {} techniques) - mappings validated.".format(
        idx.get("attack_version", "?"), len(known)))
    if bad:
        log_cb("[!] {} technique code(s) used by this app were not found in the current "
               "dataset (renamed/deprecated?): {}".format(len(bad), ", ".join(bad)))


class Recon:
    """Recon + light active-check engine. All network calls happen off the GUI thread."""

    def __init__(self, domain, log_cb, opts):
        self.domain = domain.strip().lower()
        self.log = log_cb
        self.opts = opts
        self.stop_flag = threading.Event()
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)

        self.subdomains = []       # [{host, url, status, title, server, tech, headers_missing}]
        self.crawled_urls = set()
        self.js_files = set()
        self.js_endpoints = set()
        self.params = {}           # url -> set(param names)
        self.reflections = []      # [{url, param, evidence}]
        self.open_redirects = []   # [{url, param}]
        self.exposures = []        # [{host, kind, detail, severity}]
        self.possible_secrets = [] # [{source, snippet}]
        self.jwts = []             # [{host, token}]
        self.cors_hosts = []       # [{host, url, header}]
        self.suggestions = []      # built at the end

    def stop(self):
        self.stop_flag.set()

    def _get(self, url, **kw):
        kw.setdefault("timeout", self.opts.get("timeout", 6))
        kw.setdefault("allow_redirects", True)
        kw.setdefault("verify", True)
        try:
            return self.session.get(url, **kw)
        except requests.exceptions.SSLError:
            try:
                return self.session.get(url, verify=False, **{k: v for k, v in kw.items() if k != "verify"})
            except Exception:
                return None
        except Exception:
            return None

    # ---------------- subdomain enumeration (passive, crt.sh) ----------------

    def enumerate_subdomains(self):
        self.log("[*] Querying crt.sh for certificate-transparency subdomains...")
        hosts = {self.domain, "www." + self.domain}
        try:
            r = self.session.get(
                "https://crt.sh/?q=%25.{}&output=json".format(self.domain),
                timeout=15,
            )
            if r is not None and r.ok:
                data = r.json()
                for entry in data:
                    for name in str(entry.get("name_value", "")).split("\n"):
                        name = name.strip().lower().lstrip("*.")
                        if name.endswith(self.domain) and " " not in name:
                            hosts.add(name)
                self.log("[+] crt.sh returned {} candidate hosts".format(len(hosts)))
            else:
                self.log("[!] crt.sh lookup failed or rate-limited; continuing with base host only")
        except Exception as e:
            self.log("[!] crt.sh lookup error: {}".format(e))

        # optional: use subfinder/amass, bundled in tools\ or found on PATH
        for tool in ("subfinder", "amass"):
            path = find_tool_path(tool)
            if not path:
                continue
            self.log("[*] Found {}, running it too...".format(tool))
            try:
                if tool == "subfinder":
                    cmd = [path, "-d", self.domain, "-silent"]
                else:
                    cmd = [path, "enum", "-passive", "-d", self.domain]
                out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8",
                                      errors="replace", env=child_env(), timeout=90)
                for line in out.stdout.splitlines():
                    line = line.strip().lower()
                    if line.endswith(self.domain):
                        hosts.add(line)
            except Exception as e:
                self.log("[!] {} run failed: {}".format(tool, e))

        cap = self.opts.get("max_subdomains", 150)
        hosts = sorted(hosts)[:cap]
        self.log("[*] Checking liveness of {} hosts (this can take a minute)...".format(len(hosts)))
        with ThreadPoolExecutor(max_workers=self.opts.get("concurrency", 10)) as ex:
            futures = {ex.submit(self._probe_host, h): h for h in hosts}
            for fut in as_completed(futures):
                if self.stop_flag.is_set():
                    break
                rec = fut.result()
                if rec:
                    self.subdomains.append(rec)
                    self.log("    [+] {} -> {} ({})".format(rec["host"], rec["status"], rec["title"][:60]))
        self.subdomains.sort(key=lambda r: r["host"])
        return self.subdomains

    def _probe_host(self, host):
        for scheme in ("https://", "http://"):
            url = scheme + host
            r = self._get(url)
            if r is None:
                continue
            title_m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            title = re.sub(r"\s+", " ", title_m.group(1)).strip() if title_m else ""
            server = r.headers.get("Server", "")
            tech = self._fingerprint(r)
            missing = [h for h in SECURITY_HEADERS if h not in r.headers]
            if missing:
                self.exposures.append({
                    "host": host, "kind": "Missing security headers",
                    "detail": ", ".join(missing), "severity": "P5",
                })
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            if acao and (acao == "*" or "Access-Control-Allow-Credentials" in r.headers):
                self.cors_hosts.append({"host": host, "url": r.url, "header": acao})
            blob = " ".join("{}={}".format(k, v) for k, v in r.headers.items()) + " " + \
                   " ".join("{}={}".format(k, v) for k, v in r.cookies.items())
            for m in JWT_RE.finditer(blob):
                self.jwts.append({"host": host, "token": m.group(0)})
            return {
                "host": host, "url": r.url, "status": r.status_code,
                "title": title, "server": server, "tech": tech,
            }
        return None

    @staticmethod
    def _fingerprint(resp):
        hints = []
        headers_blob = " ".join(["{}:{}".format(k, v) for k, v in resp.headers.items()]).lower()
        cookies = " ".join(resp.cookies.keys()).lower()
        body_head = resp.text[:2000].lower() if resp.text else ""
        checks = [
            ("wordpress", ["wp-content", "wp-json", "wordpress"]),
            ("php", ["phpsessid", "x-powered-by: php", ".php"]),
            ("laravel", ["laravel_session", "x-powered-by: php"]),
            ("django", ["csrftoken", "django"]),
            ("spring/java", ["jsessionid", "x-application-context"]),
            ("aspnet", ["asp.net", ".aspx", "x-aspnet-version", "x-powered-by: asp.net"]),
            ("nodejs/express", ["x-powered-by: express", "connect.sid"]),
            ("react/spa", ["id=\"root\"", "__next", "react"]),
            ("graphql", ["graphql"]),
            ("nginx", ["server: nginx"]),
            ("cloudflare", ["cf-ray", "server: cloudflare"]),
        ]
        for label, needles in checks:
            for n in needles:
                if n in headers_blob or n in cookies or n in body_head:
                    hints.append(label)
                    break
        return sorted(set(hints))

    # ---------------- crawl + endpoint/param discovery ----------------

    def crawl_and_discover(self):
        live = [s for s in self.subdomains if s["status"] and s["status"] < 400]
        if not live:
            self.log("[!] No live hosts to crawl.")
            return
        max_pages = self.opts.get("crawl_max_pages", 40)
        for rec in live[: self.opts.get("crawl_max_hosts", 5)]:
            if self.stop_flag.is_set():
                break
            self._crawl_host(rec["url"], max_pages)
            self._check_common_paths(rec["url"], rec["host"])

    def _crawl_host(self, base_url, max_pages):
        self.log("[*] Crawling {} (max {} pages)...".format(base_url, max_pages))
        seen = set()
        queue_ = [base_url]
        domain_root = urlparse(base_url).netloc
        while queue_ and len(seen) < max_pages and not self.stop_flag.is_set():
            url = queue_.pop(0)
            if url in seen:
                continue
            seen.add(url)
            r = self._get(url)
            if r is None or "text/html" not in r.headers.get("Content-Type", ""):
                continue
            self.crawled_urls.add(url)
            self._record_params(url)
            for m in re.finditer(r'''(?:href|src|action)\s*=\s*["']([^"'#\s]+)''', r.text, re.I):
                link = urljoin(url, m.group(1))
                p = urlparse(link)
                if p.netloc != domain_root:
                    continue
                if link.lower().endswith((".js",)):
                    self.js_files.add(link)
                elif link not in seen:
                    queue_.append(link)
        self.log("    [+] {} pages crawled, {} JS files found".format(len(seen), len(self.js_files)))
        for js in list(self.js_files)[: self.opts.get("max_js_files", 15)]:
            self._mine_js(js)

    def _record_params(self, url):
        qs = parse_qs(urlsplit(url).query)
        if qs:
            self.params.setdefault(url, set()).update(qs.keys())

    def _mine_js(self, js_url):
        r = self._get(js_url)
        if r is None:
            return
        body = r.text
        for m in re.finditer(r'''["'](\/[a-zA-Z0-9_\-\/\.]{2,80})["']''', body):
            path = m.group(1)
            if any(path.endswith(ext) for ext in (".png", ".jpg", ".svg", ".css", ".woff", ".woff2")):
                continue
            self.js_endpoints.add(urljoin(js_url, path))
        secret_patterns = [
            (r"AKIA[0-9A-Z]{16}", "AWS Access Key"),
            (r"sk_live_[0-9a-zA-Z]{16,}", "Stripe live secret key"),
            (r"(?:api[_-]?key|apikey|secret|token)[\"']?\s*[:=]\s*[\"']([A-Za-z0-9\-_]{16,})[\"']", "Possible hardcoded API key/secret"),
        ]
        for pattern, label in secret_patterns:
            for m in re.finditer(pattern, body, re.I):
                self.possible_secrets.append({"source": js_url, "kind": label, "snippet": m.group(0)[:80]})

    def _check_common_paths(self, base_url, host):
        checks = [
            (".git/HEAD", "ref:", "Exposed .git directory", "P2"),
            (".env", "=", "Exposed .env file", "P1"),
            ("wp-json/wp/v2/users", '"id"', "WordPress user enumeration", "P4"),
            ("swagger.json", '"paths"', "Exposed Swagger/OpenAPI spec", "P4"),
            ("openapi.json", '"paths"', "Exposed OpenAPI spec", "P4"),
            ("graphql", "query", "GraphQL endpoint present", "P5"),
            (".well-known/security.txt", "contact", "security.txt present (informational)", "P5"),
        ]
        for path, needle, label, sev in checks:
            if self.stop_flag.is_set():
                return
            url = base_url.rstrip("/") + "/" + path
            r = self._get(url)
            if r is not None and r.status_code == 200 and needle.lower() in r.text[:3000].lower():
                self.exposures.append({"host": host, "kind": label, "detail": url, "severity": sev})
                self.log("    [!] {}: {}".format(label, url))

    # ---------------- safe active checks: reflection + open redirect ----------------

    def test_params(self):
        all_urls = set(self.params.keys())
        if not all_urls:
            self.log("[*] No parameterized URLs discovered to test.")
            return
        self.log("[*] Testing {} parameterized URL(s) for reflection / open-redirect...".format(len(all_urls)))
        budget = self.opts.get("max_param_tests", 60)
        tested = 0
        for url in all_urls:
            if tested >= budget or self.stop_flag.is_set():
                break
            for param in self.params[url]:
                if tested >= budget:
                    break
                tested += 1
                self._test_reflection(url, param)
                pname = param.lower()
                if pname in REDIRECT_PARAM_HINTS:
                    self._test_open_redirect(url, param)
        self.log("    [+] {} reflection findings, {} open-redirect findings".format(
            len(self.reflections), len(self.open_redirects)))

    def _test_reflection(self, url, param):
        mk = marker()
        parts = urlsplit(url)
        qs = parse_qs(parts.query)
        qs[param] = [mk]
        new_query = "&".join("{}={}".format(k, v[0]) for k, v in qs.items())
        test_url = parts._replace(query=new_query).geturl()
        r = self._get(test_url)
        if r is not None and mk in r.text:
            idx = r.text.find(mk)
            evidence = r.text[max(0, idx - 20):idx + len(mk) + 20]
            self.reflections.append({"url": test_url, "param": param, "evidence": evidence.strip()})

    def _test_open_redirect(self, url, param):
        target = "https://example.org/bhq-redirect-check"
        parts = urlsplit(url)
        qs = parse_qs(parts.query)
        qs[param] = [target]
        new_query = "&".join("{}={}".format(k, v[0]) for k, v in qs.items())
        test_url = parts._replace(query=new_query).geturl()
        r = self._get(test_url, allow_redirects=False)
        if r is not None and r.status_code in (301, 302, 303, 307, 308):
            loc = r.headers.get("Location", "")
            if "example.org" in loc:
                self.open_redirects.append({"url": test_url, "param": param})

    # ---------------- suggestion engine ----------------

    def build_suggestions(self):
        s = []

        for exp in self.exposures:
            sev = exp["severity"]
            base = "https://" + exp["host"]
            kind = exp["kind"].lower()
            if "git" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "git-dumper",
                                    TOOL_HINTS["git-dumper"].format(base=base, host=exp["host"]),
                                    "A05", "T1213.003"))
                s.append(self._sug("Scan dumped source for known-vulnerable dependencies", "P3",
                                    "./loot/{}-git".format(exp["host"]), "trivy",
                                    TOOL_HINTS["trivy"].format(host=exp["host"]), "A06", "T1588.006"))
            elif ".env" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "Open {} directly in a browser/curl and review for live credentials.".format(exp["detail"]),
                                    "A05", "T1552.001"))
            elif "swagger" in kind or "openapi" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "curl -s \"{}\" | jq '.paths | keys'".format(exp["detail"]),
                                    "A05,API9", "T1213"))
            elif "graphql" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "graphql-introspect",
                                    TOOL_HINTS["graphql-introspect"].format(url=exp["detail"]),
                                    "A05,API9", "T1213"))
            elif "wordpress" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "wpscan",
                                    TOOL_HINTS["wpscan"].format(base=base), "A06", "T1588.006"))
            elif "missing security headers" in kind:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "Add the missing headers; re-check with nuclei's misconfiguration templates.",
                                    "A05", "T1592.002"))
            else:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "Review header/config hardening.", "A05", "T1592.002"))

        for ref in self.reflections:
            s.append(self._sug("Reflected parameter (possible XSS)", "P2", ref["url"],
                                "dalfox", TOOL_HINTS["dalfox"].format(url=ref["url"]), "A03", "T1059"))

        for red in self.open_redirects:
            s.append(self._sug("Open redirect", "P3", "{} (param: {})".format(red["url"], red["param"]),
                                "manual review", "Confirm impact (token leak / phishing chain) manually.",
                                "A01", "T1204.001"))

        for cors in self.cors_hosts:
            s.append(self._sug("Permissive CORS header ({})".format(cors["header"]), "P3", cors["url"],
                                "corsy", TOOL_HINTS["corsy"].format(url=cors["url"]), "A05,API8", "T1539"))

        for jwt in self.jwts:
            s.append(self._sug("JWT observed in traffic", "P4", jwt["host"], "jwt_tool",
                                TOOL_HINTS["jwt_tool"].format(token=jwt["token"]), "A07,API2", "T1606"))

        ssrf_seen = False
        for url, params in self.params.items():
            host = urlparse(url).netloc
            path = urlparse(url).path.lower()
            for p in params:
                pl = p.lower()
                if pl in SQLI_PARAM_HINTS:
                    s.append(self._sug("SQLi candidate parameter '{}'".format(p), "P2", url,
                                        "sqlmap", TOOL_HINTS["sqlmap"].format(url=url), "A03", "T1190"))
                if pl in CMDI_PARAM_HINTS:
                    s.append(self._sug("OS command-injection candidate parameter '{}'".format(p), "P1", url,
                                        "commix", TOOL_HINTS["commix"].format(url=url), "A03", "T1190"))
                if pl in LFI_PARAM_HINTS:
                    s.append(self._sug("LFI/path-traversal candidate parameter '{}'".format(p), "P2", url,
                                        "ffuf", TOOL_HINTS["ffuf-lfi"].format(
                                            url_marker=url.replace(p + "=" + parse_qs(urlsplit(url).query).get(p, [""])[0],
                                                                    p + "=FUZZ")), "A01", "T1190"))
                if pl in SSRF_PARAM_HINTS:
                    s.append(self._sug("SSRF candidate parameter '{}'".format(p), "P2", url,
                                        "manual review / interactsh-client",
                                        "Point {} at your interactsh listener URL and watch for a callback.".format(p),
                                        "A10,API7", "T1552.005"))
                    ssrf_seen = True
            if any(h in path for h in UPLOAD_PATH_HINTS):
                s.append(self._sug("Upload endpoint discovered", "P3", url, "manual review",
                                    "Test extension/MIME/magic-byte bypass and storage location manually.",
                                    "A04", "T1505.003"))
            if any(h in path for h in ADMIN_PATH_HINTS):
                s.append(self._sug("Admin/internal path discovered", "P3", url, "manual review",
                                    "Test for missing authz / IDOR / default creds on this panel.",
                                    "A01,API5", "T1078"))

        if ssrf_seen:
            s.append(self._sug("Start an out-of-band listener for blind SSRF/XXE", "P5", self.domain,
                                "interactsh-client", TOOL_HINTS["interactsh-client"], "A10,API7", "T1552.005"))

        for host_rec in self.subdomains:
            if "wordpress" in host_rec.get("tech", []):
                base = host_rec["url"]
                s.append(self._sug("WordPress detected", "P4", base, "wpscan",
                                    TOOL_HINTS["wpscan"].format(base=base), "A06", "T1592.002"))

        if self.js_endpoints:
            sample = list(self.js_endpoints)[:1][0] if self.js_endpoints else ""
            s.append(self._sug("{} endpoint(s) mined from JS bundles".format(len(self.js_endpoints)), "P5",
                                sample, "manual review", "Review js_endpoints list for undocumented API routes.",
                                "A01,API9", "T1592.002"))

        for sec in self.possible_secrets:
            s.append(self._sug(sec["kind"], "P1", sec["source"], "manual review",
                                "Rotate/revoke immediately if confirmed live: {}".format(sec["snippet"]),
                                "A02", "T1552.001"))

        for host_rec in self.subdomains:
            if host_rec["host"] in (self.domain, "www." + self.domain) and \
                    host_rec["status"] and host_rec["status"] < 400:
                s.append(self._sug("Run a nuclei template scan", "P4", host_rec["url"], "nuclei",
                                    TOOL_HINTS["nuclei"].format(url=host_rec["url"],
                                                                 tags="cve,exposure,misconfig"),
                                    "A06", "T1595.002"))
                if host_rec["url"].startswith("https://"):
                    s.append(self._sug("Check TLS config / cipher suites", "P5", host_rec["host"], "tlsx",
                                        TOOL_HINTS["tlsx"].format(host=host_rec["host"]), "A02", "T1592.002"))

        sev_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "P5": 4}
        s.sort(key=lambda x: sev_order.get(x["severity"], 5))
        self.suggestions = s
        return s

    @staticmethod
    def _sug(finding, severity, location, tool, command, owasp="", mitre=""):
        labels = []
        for code in str(owasp).split(","):
            code = code.strip()
            if code:
                labels.append(OWASP.get(code) or OWASP_API.get(code) or code)
        return {"finding": finding, "severity": severity, "location": location,
                "tool": tool, "command": command,
                "owasp": " · ".join(labels), "mitre": mitre_lookup(mitre), "mitre_id": mitre}


class App:
    def __init__(self, root):
        self.root = root
        root.title(APP_NAME)
        root.geometry("1180x760")
        self.q = queue.Queue()
        self.recon = None
        self.recon_thread = None
        self.findings = []
        self.project_file = None

        self._build_ui()
        self._refresh_mitre_ref()
        self.refresh_setup_status()
        self.root.after(100, self._drain_queue)
        self.root.after(300, self._maybe_prompt_first_run_setup)

    # ---------------- UI ----------------

    def _build_ui(self):
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Target domain:").pack(side="left")
        self.domain_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.domain_var, width=32).pack(side="left", padx=6)

        self.authorized_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="I am authorized to actively test this target",
                         variable=self.authorized_var).pack(side="left", padx=12)

        self.start_btn = ttk.Button(top, text="Start Recon", command=self.start_recon)
        self.start_btn.pack(side="left", padx=4)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop_recon, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        ttk.Button(top, text="Save Project", command=self.save_project).pack(side="right", padx=4)
        ttk.Button(top, text="Load Project", command=self.load_project).pack(side="right", padx=4)

        self.status_var = tk.StringVar(value="Idle.")
        ttk.Label(self.root, textvariable=self.status_var, padding=(10, 0)).pack(fill="x")

        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=8)

        self._build_setup_tab()
        self._build_log_tab()
        self._build_hosts_tab()
        self._build_endpoints_tab()
        self._build_suggestions_tab()
        self._build_mitre_tab()
        self._build_findings_tab()
        self._build_about_tab()

    def _build_setup_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text="Setup")
        self.tab_setup = f

        ttk.Label(f, text="Prerequisites", font=("", 11, "bold")).pack(anchor="w")
        ttk.Label(f, text="Everything below downloads/configures itself into the tools\\ "
                           "folder next to this app - nothing needs installing by hand.",
                  wraplength=820).pack(anchor="w", pady=(0, 10))

        status = ttk.Frame(f)
        status.pack(fill="x", pady=(0, 10))
        self.setup_tools_var = tk.StringVar(value="Checking...")
        self.setup_attack_var = tk.StringVar(value="Checking...")
        row1 = ttk.Frame(status)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Attack tools:", width=22).pack(side="left")
        ttk.Label(row1, textvariable=self.setup_tools_var).pack(side="left")
        row2 = ttk.Frame(status)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="MITRE ATT&CK data:", width=22).pack(side="left")
        ttk.Label(row2, textvariable=self.setup_attack_var).pack(side="left")

        btns = ttk.Frame(f)
        btns.pack(fill="x", pady=(0, 10))
        ttk.Button(btns, text="Download / Update Attack Tools",
                   command=lambda: self.run_setup_script("fetch_tools.py")).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Download / Update MITRE ATT&CK Data",
                   command=lambda: self.run_setup_script("fetch_attack_data.py")).pack(side="left", padx=(0, 8))
        ttk.Button(btns, text="Refresh Status", command=self.refresh_setup_status).pack(side="left")

        ttk.Label(f, text="Both are safe to re-run any time - already-vendored tools are "
                           "skipped, compiled binaries and the ATT&CK dataset are re-fetched "
                           "at their current release. Progress streams into the Recon Log tab.",
                  wraplength=820, foreground="#888").pack(anchor="w", pady=(4, 0))

    def refresh_setup_status(self):
        tools_dir = bundled_tools_dir()
        found_bin = [t for t in list(GO_TOOL_NAMES) if find_tool_path(t)]
        found_py = [t for t in PY_SCRIPT_TOOLS
                    if os.path.isfile(os.path.join(tools_dir, PY_SCRIPT_TOOLS[t]))]
        if found_bin or found_py:
            self.setup_tools_var.set("{} compiled + {} vendored found in {}".format(
                len(found_bin), len(found_py), tools_dir))
        else:
            self.setup_tools_var.set("Not found - click \"Download / Update Attack Tools\" below")

        idx = load_attack_index()
        if idx:
            self.setup_attack_var.set("Loaded - ATT&CK v{}, {} techniques".format(
                idx.get("attack_version", "?"), len(idx.get("techniques", {}))))
        else:
            self.setup_attack_var.set("Not found - click \"Download / Update MITRE ATT&CK Data\" below")

    def _maybe_prompt_first_run_setup(self):
        tools_dir = bundled_tools_dir()
        any_bin = any(find_tool_path(t) for t in GO_TOOL_NAMES)
        any_py = any(os.path.isfile(os.path.join(tools_dir, p)) for p in PY_SCRIPT_TOOLS.values())
        any_attack = bool(load_attack_index())
        if any_bin or any_py or any_attack:
            return  # something's already configured - don't nag on every launch
        if messagebox.askyesno(
                APP_NAME,
                "No attack tools or MITRE ATT&CK data found yet.\n\n"
                "Download and configure everything now? This fetches the attack tools "
                "(a few hundred MB) and the MITRE ATT&CK dataset (~50MB) into tools\\ "
                "next to this app - one-time, safe to re-run later from the Setup tab.\n\n"
                "Requires an internet connection."):
            self.nb.select(self.tab_setup)
            self.run_setup_script("fetch_tools.py")
            self.run_setup_script("fetch_attack_data.py")

    def run_setup_script(self, script_name):
        script_path = os.path.join(bundled_tools_dir(), script_name)
        if not os.path.isfile(script_path):
            messagebox.showerror(APP_NAME, "{} not found at {}\n\nIf you're running the built "
                                            "exe, it ships in tools\\ next to it - make sure you "
                                            "copied the whole dist\\ folder, not just the "
                                            "exe.".format(script_name, script_path))
            return
        if getattr(sys, "frozen", False):
            argv = [sys.executable, "--bhq-pyscript", script_path]
        else:
            argv = [sys.executable, script_path]

        self.nb.select(self.tab_log)
        self.log("[*] Running {} ...".format(script_name))

        def worker():
            try:
                proc = subprocess.Popen(argv, cwd=bundled_tools_dir(), stdout=subprocess.PIPE,
                                         stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                         errors="replace", env=child_env(), bufsize=1)
                for line in proc.stdout:
                    self.log(line.rstrip("\n"))
                proc.wait()
                self.log("[*] {} finished (exit code {}).".format(script_name, proc.returncode))
            except Exception as e:
                self.log("[!] {} failed to run: {}".format(script_name, e))
            self.q.put(("setup_refresh", None))

        threading.Thread(target=worker, daemon=True).start()

    def _build_log_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Recon Log")
        self.tab_log = f
        self.log_text = tk.Text(f, wrap="word", state="disabled", bg="#0d1417", fg="#d7e3e6",
                                 insertbackground="#d7e3e6", font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, side="left")
        sb = ttk.Scrollbar(f, command=self.log_text.yview)
        sb.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=sb.set)

    def _build_hosts_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Live Hosts")
        cols = ("host", "status", "title", "server", "tech")
        self.hosts_tree = ttk.Treeview(f, columns=cols, show="headings")
        widths = {"host": 220, "status": 60, "title": 260, "server": 140, "tech": 220}
        for c in cols:
            self.hosts_tree.heading(c, text=c.capitalize())
            self.hosts_tree.column(c, width=widths[c], anchor="w")
        self.hosts_tree.pack(fill="both", expand=True)

    def _build_endpoints_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Endpoints & Params")
        cols = ("url", "params")
        self.ep_tree = ttk.Treeview(f, columns=cols, show="headings")
        self.ep_tree.heading("url", text="URL")
        self.ep_tree.heading("params", text="Parameters")
        self.ep_tree.column("url", width=680, anchor="w")
        self.ep_tree.column("params", width=380, anchor="w")
        self.ep_tree.pack(fill="both", expand=True)

    def _build_suggestions_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Attack Suggestions")

        cols = ("severity", "owasp", "mitre", "finding", "location", "tool")
        self.sug_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        widths = {"severity": 55, "owasp": 200, "mitre": 230, "finding": 240, "location": 260, "tool": 110}
        headings = {"owasp": "OWASP Top 10", "mitre": "MITRE ATT&CK"}
        for c in cols:
            self.sug_tree.heading(c, text=headings.get(c, c.capitalize()))
            self.sug_tree.column(c, width=widths[c], anchor="w")
        self.sug_tree.pack(fill="both", expand=True)
        self.sug_tree.bind("<<TreeviewSelect>>", self._on_suggestion_select)

        bottom = ttk.Frame(f, padding=(0, 8))
        bottom.pack(fill="x")
        ttk.Label(bottom, text="Command:").pack(side="left")
        self.cmd_var = tk.StringVar()
        ttk.Entry(bottom, textvariable=self.cmd_var, width=90).pack(side="left", padx=6, fill="x", expand=True)
        ttk.Button(bottom, text="Copy", command=self._copy_cmd).pack(side="left", padx=4)
        self.run_btn = ttk.Button(bottom, text="Run (if tool installed)", command=self._run_cmd)
        self.run_btn.pack(side="left", padx=4)
        ttk.Button(bottom, text="Add as Finding", command=self._suggestion_to_finding).pack(side="left", padx=4)
        ttk.Button(bottom, text="Export ATT&CK Navigator layer...",
                   command=self.export_navigator_layer).pack(side="right", padx=4)

    def _build_mitre_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="MITRE Reference")

        top = ttk.Frame(f, padding=(0, 0, 0, 6))
        top.pack(fill="x")
        self.mitre_status_var = tk.StringVar(value="Loading...")
        ttk.Label(top, textvariable=self.mitre_status_var).pack(side="left")
        self.mitre_search_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.mitre_search_var, width=30).pack(side="right")
        ttk.Label(top, text="Filter:").pack(side="right", padx=(0, 4))
        self.mitre_search_var.trace_add("write", lambda *a: self._refresh_mitre_ref())

        cols = ("id", "tactic", "name")
        self.mitre_tree = ttk.Treeview(f, columns=cols, show="headings")
        widths = {"id": 90, "tactic": 180, "name": 480}
        for c in cols:
            self.mitre_tree.heading(c, text=c.capitalize())
            self.mitre_tree.column(c, width=widths[c], anchor="w")
        self.mitre_tree.pack(fill="both", expand=True)

        ttk.Label(f, text="Curated to the web-application exploitation kill chain "
                           "(reconnaissance through collection/exfiltration). Open a "
                           "technique's page for details: attack.mitre.org/techniques/<ID>",
                  wraplength=900, padding=(0, 6)).pack(anchor="w")

    def _build_findings_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Findings Log")
        self.tab_findings = f

        form = ttk.LabelFrame(f, text="New finding", padding=8)
        form.pack(fill="x", padx=4, pady=4)
        self.f_title = tk.StringVar()
        self.f_sev = tk.StringVar(value="P3")
        self.f_target = tk.StringVar()
        self.f_status = tk.StringVar(value="Draft")

        row1 = ttk.Frame(form)
        row1.pack(fill="x", pady=2)
        ttk.Label(row1, text="Title").pack(side="left")
        ttk.Entry(row1, textvariable=self.f_title, width=50).pack(side="left", padx=6)
        ttk.Label(row1, text="Severity").pack(side="left", padx=(12, 0))
        ttk.Combobox(row1, textvariable=self.f_sev, values=["P1", "P2", "P3", "P4", "P5"], width=6,
                     state="readonly").pack(side="left", padx=6)
        ttk.Label(row1, text="Status").pack(side="left", padx=(12, 0))
        ttk.Combobox(row1, textvariable=self.f_status,
                     values=["Draft", "Submitted", "Triaged", "Duplicate", "Resolved / Paid", "N/A"],
                     width=16, state="readonly").pack(side="left", padx=6)

        row2 = ttk.Frame(form)
        row2.pack(fill="x", pady=2)
        ttk.Label(row2, text="Target/URL").pack(side="left")
        ttk.Entry(row2, textvariable=self.f_target, width=80).pack(side="left", padx=6, fill="x", expand=True)

        self.f_desc = tk.Text(form, height=4)
        self.f_desc.pack(fill="x", pady=4)
        ttk.Button(form, text="Add finding", command=self.add_finding).pack(anchor="e")

        listwrap = ttk.Frame(f)
        listwrap.pack(fill="both", expand=True, padx=4, pady=4)
        cols = ("severity", "title", "target", "status")
        self.find_tree = ttk.Treeview(listwrap, columns=cols, show="headings")
        for c in cols:
            self.find_tree.heading(c, text=c.capitalize())
        self.find_tree.column("severity", width=60)
        self.find_tree.column("title", width=340)
        self.find_tree.column("target", width=340)
        self.find_tree.column("status", width=120)
        self.find_tree.pack(fill="both", expand=True)

        actions = ttk.Frame(f, padding=(0, 6))
        actions.pack(fill="x")
        ttk.Button(actions, text="Delete selected", command=self.delete_finding).pack(side="left", padx=4)
        ttk.Button(actions, text="Export Markdown report...", command=self.export_report).pack(side="left", padx=4)

    def _build_about_tab(self):
        f = ttk.Frame(self.nb, padding=16)
        self.nb.add(f, text="Legal / About")
        msg = (
            "Bug Hunt HQ performs ACTIVE requests against the domain you enter: subdomain "
            "liveness checks, crawling, JS mining, parameter reflection tests, open-redirect "
            "probes, and checks for exposed .git/.env/config files.\n\n"
            "Only run this against assets you own or are explicitly authorized to test "
            "(a bug bounty program's in-scope assets, a client engagement, or your own lab).\n\n"
            "The 'Attack Suggestions' tab never auto-launches exploitation tools. It shows a "
            "ready-to-run command line; you review and run it yourself, and only if that tool "
            "is already installed on your machine.\n\n"
            "All project data is stored locally on this computer only (Save Project / Load "
            "Project as a .json file). Nothing is sent anywhere except the target you specify "
            "and crt.sh for passive subdomain lookup."
        )
        ttk.Label(f, text=msg, wraplength=900, justify="left").pack(anchor="w")

    # ---------------- recon control ----------------

    def log(self, msg):
        self.q.put(("log", msg))

    def start_recon(self):
        domain = self.domain_var.get().strip()
        if not domain:
            messagebox.showwarning(APP_NAME, "Enter a target domain first.")
            return
        if not self.authorized_var.get():
            messagebox.showwarning(APP_NAME, "Confirm you are authorized to test this target before starting.")
            return
        domain = re.sub(r"^https?://", "", domain).split("/")[0]

        self.hosts_tree.delete(*self.hosts_tree.get_children())
        self.ep_tree.delete(*self.ep_tree.get_children())
        self.sug_tree.delete(*self.sug_tree.get_children())
        self.log_text.config(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.config(state="disabled")

        opts = {"timeout": 6, "concurrency": 10, "max_subdomains": 150,
                "crawl_max_pages": 40, "crawl_max_hosts": 5, "max_js_files": 15,
                "max_param_tests": 60}
        self.recon = Recon(domain, self.log, opts)
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_var.set("Running recon against {} ...".format(domain))
        validate_mitre_codes(self.log)

        def worker():
            try:
                self.recon.enumerate_subdomains()
                self.q.put(("hosts", None))
                if self.recon.stop_flag.is_set():
                    return
                self.recon.crawl_and_discover()
                self.q.put(("endpoints", None))
                if self.recon.stop_flag.is_set():
                    return
                self.recon.test_params()
                self.recon.build_suggestions()
                self.q.put(("suggestions", None))
                self.log("[*] Recon complete.")
            except Exception as e:
                self.log("[!] Recon crashed: {}".format(e))
            finally:
                self.q.put(("done", None))

        self.recon_thread = threading.Thread(target=worker, daemon=True)
        self.recon_thread.start()

    def stop_recon(self):
        if self.recon:
            self.recon.stop()
            self.log("[*] Stop requested, finishing current request(s)...")

    def _drain_queue(self):
        try:
            while True:
                kind, payload = self.q.get_nowait()
                if kind == "log":
                    self.log_text.config(state="normal")
                    self.log_text.insert("end", payload + "\n")
                    self.log_text.see("end")
                    self.log_text.config(state="disabled")
                elif kind == "hosts":
                    self._refresh_hosts()
                elif kind == "endpoints":
                    self._refresh_endpoints()
                elif kind == "suggestions":
                    self._refresh_suggestions()
                elif kind == "done":
                    self.start_btn.config(state="normal")
                    self.stop_btn.config(state="disabled")
                    self.status_var.set("Recon finished.")
                elif kind == "setup_refresh":
                    self.refresh_setup_status()
                    self._refresh_mitre_ref()
        except queue.Empty:
            pass
        self.root.after(150, self._drain_queue)

    def _refresh_hosts(self):
        self.hosts_tree.delete(*self.hosts_tree.get_children())
        for rec in self.recon.subdomains:
            self.hosts_tree.insert("", "end", values=(
                rec["host"], rec["status"], rec["title"], rec["server"], ", ".join(rec["tech"])))

    def _refresh_endpoints(self):
        self.ep_tree.delete(*self.ep_tree.get_children())
        for url, params in self.recon.params.items():
            self.ep_tree.insert("", "end", values=(url, ", ".join(sorted(params))))
        for ep in sorted(self.recon.js_endpoints):
            self.ep_tree.insert("", "end", values=(ep, "(from JS)"))

    def _refresh_suggestions(self):
        self.sug_tree.delete(*self.sug_tree.get_children())
        for s in self.recon.suggestions:
            self.sug_tree.insert("", "end", values=(s["severity"], s["owasp"], s["mitre"],
                                                      s["finding"], s["location"], s["tool"]),
                                  tags=(s["severity"],))
        # Light, theme-appropriate tints (this app defaults to a light ttk
        # theme on Windows) with a matching dark foreground for readability -
        # not the near-black maroon/olive this used to hardcode, which read
        # as broken against the rest of the light UI.
        self.sug_tree.tag_configure("P1", background="#fbe1e1", foreground="#8a1414")
        self.sug_tree.tag_configure("P2", background="#fbe7d6", foreground="#8a4b12")
        self.sug_tree.tag_configure("P3", background="#faf1cf", foreground="#7a5f08")
        self.sug_tree.tag_configure("P4", background="#dfe9f9", foreground="#1d4ed8")
        self.sug_tree.tag_configure("P5", background="#eef1f2", foreground="#475569")

    def _on_suggestion_select(self, event):
        sel = self.sug_tree.selection()
        if not sel:
            return
        idx = self.sug_tree.index(sel[0])
        s = self.recon.suggestions[idx]
        self.cmd_var.set(s["command"])

    def _copy_cmd(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.cmd_var.get())
        self.status_var.set("Command copied to clipboard.")

    # ---------------- MITRE reference + Navigator export ----------------

    def _refresh_mitre_ref(self):
        self.mitre_tree.delete(*self.mitre_tree.get_children())
        idx = load_attack_index()
        subset = load_attack_webapp_subset()
        if not idx or not subset:
            self.mitre_status_var.set(
                "No local MITRE ATT&CK dataset. Run tools\\fetch_attack_data.py once to populate this tab.")
            return
        techniques = idx.get("techniques", {})
        ids = subset.get("technique_ids", [])
        self.mitre_status_var.set("ATT&CK v{} - {} web-app-relevant techniques".format(
            idx.get("attack_version", "?"), len(ids)))
        q = self.mitre_search_var.get().strip().lower()
        for tid in ids:
            rec = techniques.get(tid)
            if not rec:
                continue
            tactic = "/".join(rec["tactics_display"])
            if q and q not in tid.lower() and q not in rec["name"].lower() and q not in tactic.lower():
                continue
            self.mitre_tree.insert("", "end", values=(tid, tactic, rec["name"]))

    def export_navigator_layer(self):
        if not self.recon or not self.recon.suggestions:
            messagebox.showinfo(APP_NAME, "Run recon first - there are no suggestions to export yet.")
            return
        counts = {}
        comments = {}
        for s in self.recon.suggestions:
            tid = s.get("mitre_id", "")
            if not tid:
                continue
            counts[tid] = counts.get(tid, 0) + 1
            comments.setdefault(tid, []).append(s["finding"])
        if not counts:
            messagebox.showinfo(APP_NAME, "None of the current suggestions carry a MITRE technique ID.")
            return
        layer = {
            "name": "Bug Hunt HQ - {} - {}".format(
                self.domain_var.get().strip() or "target", datetime.now().strftime("%Y-%m-%d")),
            "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Techniques observed during recon/triage. Import at "
                            "https://mitre-attack.github.io/attack-navigator/",
            "techniques": [
                {
                    "techniqueID": tid,
                    "score": count,
                    "comment": "; ".join(comments[tid][:5]),
                    "enabled": True,
                }
                for tid, count in sorted(counts.items())
            ],
            "gradient": {"colors": ["#ffffff", "#ff6666"], "minValue": 0,
                         "maxValue": max(counts.values())},
            "legendItems": [],
            "showTacticRowBackground": True,
            "sorting": 0,
        }
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("ATT&CK Navigator layer", "*.json")],
                                             initialfile="bughunthq-navigator-layer.json")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(layer, fh, indent=2)
        self.status_var.set("Navigator layer exported to {} - import it at mitre-attack.github.io/attack-navigator".format(path))

    def _run_cmd(self):
        cmd = self.cmd_var.get().strip()
        if not cmd:
            return
        if not self.authorized_var.get():
            messagebox.showwarning(APP_NAME, "Check the authorization box before running any tool.")
            return
        try:
            parts = shlex.split(cmd, posix=(os.name != "nt"))
        except ValueError as e:
            messagebox.showerror(APP_NAME, "Could not parse command: {}".format(e))
            return
        tool, rest = parts[0], parts[1:]
        argv = resolve_tool_argv(tool, rest)
        if argv is None:
            messagebox.showinfo(APP_NAME, "'{}' isn't bundled in tools\\ and wasn't found on PATH.\n\n"
                                           "Run tools\\fetch_tools.py once (or re-run build.bat) to "
                                           "download/vendor it, or install it yourself, then Run again.\n\n"
                                           "You can always use Copy to run the command in your own "
                                           "terminal instead.".format(tool))
            return
        self.log("[*] Running: {}".format(" ".join(argv)))

        def worker():
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8",
                                       errors="replace", env=child_env(), timeout=600)
                self.log(proc.stdout[-4000:])
                if proc.stderr:
                    self.log("[stderr] " + proc.stderr[-2000:])
            except Exception as e:
                self.log("[!] Tool run failed: {}".format(e))

        threading.Thread(target=worker, daemon=True).start()
        self.nb.select(self.tab_log)

    def _suggestion_to_finding(self):
        sel = self.sug_tree.selection()
        if not sel:
            return
        idx = self.sug_tree.index(sel[0])
        s = self.recon.suggestions[idx]
        self.f_title.set(s["finding"])
        self.f_sev.set(s["severity"])
        self.f_target.set(s["location"])
        self.nb.select(self.tab_findings)

    # ---------------- findings ----------------

    def add_finding(self):
        title = self.f_title.get().strip()
        if not title:
            messagebox.showwarning(APP_NAME, "Give the finding a title.")
            return
        finding = {
            "title": title, "severity": self.f_sev.get(), "target": self.f_target.get().strip(),
            "status": self.f_status.get(), "description": self.f_desc.get("1.0", "end").strip(),
            "created": datetime.now().isoformat(timespec="seconds"),
        }
        self.findings.append(finding)
        self.find_tree.insert("", "end", values=(finding["severity"], finding["title"],
                                                   finding["target"], finding["status"]))
        self.f_title.set("")
        self.f_target.set("")
        self.f_desc.delete("1.0", "end")

    def delete_finding(self):
        sel = self.find_tree.selection()
        if not sel:
            return
        idx = self.find_tree.index(sel[0])
        del self.findings[idx]
        self.find_tree.delete(sel[0])

    def export_report(self):
        path = filedialog.asksaveasfilename(defaultextension=".md",
                                             filetypes=[("Markdown", "*.md")],
                                             initialfile="bughunthq-report.md")
        if not path:
            return
        lines = ["# Findings Report", "", "_Generated by Bug Hunt HQ on {}_".format(
            datetime.now().strftime("%Y-%m-%d")), ""]
        for f in sorted(self.findings, key=lambda x: x["severity"]):
            lines.append("## [{}] {}".format(f["severity"], f["title"]))
            lines.append("")
            lines.append("- **Target:** `{}`".format(f["target"]))
            lines.append("- **Status:** {}".format(f["status"]))
            lines.append("")
            if f["description"]:
                lines.append(f["description"])
                lines.append("")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        self.status_var.set("Report exported to {}".format(path))

    # ---------------- project save/load ----------------

    def save_project(self):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                             filetypes=[("Bug Hunt HQ project", "*.json")],
                                             initialdir=DATA_DIR, initialfile="project.json")
        if not path:
            return
        data = {
            "domain": self.domain_var.get(),
            "findings": self.findings,
            "recon": {
                "subdomains": self.recon.subdomains if self.recon else [],
                "params": {k: sorted(v) for k, v in (self.recon.params.items() if self.recon else {})},
                "suggestions": self.recon.suggestions if self.recon else [],
            } if self.recon else None,
        }
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2)
        self.project_file = path
        self.status_var.set("Project saved to {}".format(path))

    def load_project(self):
        path = filedialog.askopenfilename(filetypes=[("Bug Hunt HQ project", "*.json")], initialdir=DATA_DIR)
        if not path:
            return
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        self.domain_var.set(data.get("domain", ""))
        self.findings = data.get("findings", [])
        self.find_tree.delete(*self.find_tree.get_children())
        for f in self.findings:
            self.find_tree.insert("", "end", values=(f["severity"], f["title"], f["target"], f["status"]))
        recon_data = data.get("recon")
        if recon_data:
            self.hosts_tree.delete(*self.hosts_tree.get_children())
            for rec in recon_data.get("subdomains", []):
                self.hosts_tree.insert("", "end", values=(
                    rec["host"], rec["status"], rec["title"], rec["server"], ", ".join(rec.get("tech", []))))
            self.ep_tree.delete(*self.ep_tree.get_children())
            for url, params in recon_data.get("params", {}).items():
                self.ep_tree.insert("", "end", values=(url, ", ".join(params)))
            self.sug_tree.delete(*self.sug_tree.get_children())
            for s in recon_data.get("suggestions", []):
                self.sug_tree.insert("", "end", values=(s["severity"], s.get("owasp", ""), s.get("mitre", ""),
                                                          s["finding"], s["location"], s["tool"]))
        self.project_file = path
        self.status_var.set("Project loaded from {}".format(path))


def main():
    # Dispatch mode: when frozen into an exe, this re-invokes the exe itself
    # to run a vendored pure-Python tool (sqlmap, git-dumper) in-process,
    # using the interpreter PyInstaller already bundled - no separate Python
    # install needed on the machine running the built .exe.
    if len(sys.argv) >= 3 and sys.argv[1] == "--bhq-pyscript":
        import runpy
        script = sys.argv[2]
        sys.argv = [script] + sys.argv[3:]
        sys.path.insert(0, os.path.dirname(script))
        runpy.run_path(script, run_name="__main__")
        return

    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
        elif "clam" in style.theme_names():
            style.theme_use("clam")
    except Exception:
        pass
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
