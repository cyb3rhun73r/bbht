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
UPLOAD_PATH_HINTS = {"upload", "file", "media", "attachment", "import"}
ADMIN_PATH_HINTS = {"admin", "manage", "dashboard", "internal", "cpanel", "wp-admin"}

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]

TOOL_HINTS = {
    "sqlmap": "sqlmap -u \"{url}\" --batch --level=2 --risk=1",
    "dalfox": "dalfox url \"{url}\"",
    "ffuf-lfi": "ffuf -u \"{url_marker}\" -w wordlists/lfi.txt -mc all",
    "ffuf-dir": "ffuf -u \"{base}/FUZZ\" -w wordlists/common.txt -mc 200,301,302,403",
    "nuclei": "nuclei -u \"{url}\" -tags {tags}",
    "wpscan": "wpscan --url \"{base}\" --enumerate vp,vt,u",
    "git-dumper": "git-dumper \"{base}/.git\" ./loot/{host}-git",
    "graphql-introspect": "curl -s -X POST \"{url}\" -H \"Content-Type: application/json\" "
                           "-d \"{{\\\"query\\\":\\\"{{__schema{{types{{name}}}}}}\\\"}}\"",
}


def marker():
    return "bhq" + "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


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

        # optional: use subfinder/amass if the user has them installed
        for tool in ("subfinder", "amass"):
            path = shutil.which(tool)
            if not path:
                continue
            self.log("[*] Found {} on PATH, running it too...".format(tool))
            try:
                if tool == "subfinder":
                    cmd = [path, "-d", self.domain, "-silent"]
                else:
                    cmd = [path, "enum", "-passive", "-d", self.domain]
                out = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
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
            if "git" in exp["kind"].lower():
                s.append(self._sug(exp["kind"], sev, exp["detail"],
                                    "git-dumper", TOOL_HINTS["git-dumper"].format(base=base, host=exp["host"])))
            elif ".env" in exp["kind"].lower():
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "Open {} directly in a browser/curl and review for live credentials.".format(exp["detail"])))
            elif "swagger" in exp["kind"].lower() or "openapi" in exp["kind"].lower():
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review",
                                    "curl -s \"{}\" | jq '.paths | keys'".format(exp["detail"])))
            elif "graphql" in exp["kind"].lower():
                s.append(self._sug(exp["kind"], sev, exp["detail"], "graphql-introspect",
                                    TOOL_HINTS["graphql-introspect"].format(url=exp["detail"])))
            elif "wordpress" in exp["kind"].lower():
                s.append(self._sug(exp["kind"], sev, exp["detail"], "wpscan",
                                    TOOL_HINTS["wpscan"].format(base=base)))
            else:
                s.append(self._sug(exp["kind"], sev, exp["detail"], "manual review", "Review header/config hardening."))

        for ref in self.reflections:
            s.append(self._sug("Reflected parameter (possible XSS)", "P2", ref["url"],
                                "dalfox", TOOL_HINTS["dalfox"].format(url=ref["url"])))

        for red in self.open_redirects:
            s.append(self._sug("Open redirect", "P3", "{} (param: {})".format(red["url"], red["param"]),
                                "manual review", "Confirm impact (token leak / phishing chain) manually."))

        for url, params in self.params.items():
            host = urlparse(url).netloc
            path = urlparse(url).path.lower()
            for p in params:
                pl = p.lower()
                if pl in SQLI_PARAM_HINTS:
                    s.append(self._sug("SQLi candidate parameter '{}'".format(p), "P2", url,
                                        "sqlmap", TOOL_HINTS["sqlmap"].format(url=url)))
                if pl in LFI_PARAM_HINTS:
                    s.append(self._sug("LFI/path-traversal candidate parameter '{}'".format(p), "P2", url,
                                        "ffuf", TOOL_HINTS["ffuf-lfi"].format(
                                            url_marker=url.replace(p + "=" + parse_qs(urlsplit(url).query).get(p, [""])[0],
                                                                    p + "=FUZZ"))))
                if pl in SSRF_PARAM_HINTS:
                    s.append(self._sug("SSRF candidate parameter '{}'".format(p), "P2", url,
                                        "manual review / Burp Collaborator",
                                        "Point {} at an out-of-band listener and watch for a callback.".format(p)))
            if any(h in path for h in UPLOAD_PATH_HINTS):
                s.append(self._sug("Upload endpoint discovered", "P3", url, "manual review",
                                    "Test extension/MIME/magic-byte bypass and storage location manually."))
            if any(h in path for h in ADMIN_PATH_HINTS):
                s.append(self._sug("Admin/internal path discovered", "P3", url, "manual review",
                                    "Test for missing authz / IDOR / default creds on this panel."))

        for host_rec in self.subdomains:
            if "wordpress" in host_rec.get("tech", []):
                base = host_rec["url"]
                s.append(self._sug("WordPress detected", "P4", base, "wpscan", TOOL_HINTS["wpscan"].format(base=base)))

        if self.js_endpoints:
            sample = list(self.js_endpoints)[:1][0] if self.js_endpoints else ""
            s.append(self._sug("{} endpoint(s) mined from JS bundles".format(len(self.js_endpoints)), "P5",
                                sample, "manual review", "Review js_endpoints list for undocumented API routes."))

        for sec in self.possible_secrets:
            s.append(self._sug(sec["kind"], "P1", sec["source"], "manual review",
                                "Rotate/revoke immediately if confirmed live: {}".format(sec["snippet"])))

        sev_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3, "P5": 4}
        s.sort(key=lambda x: sev_order.get(x["severity"], 5))
        self.suggestions = s
        return s

    @staticmethod
    def _sug(finding, severity, location, tool, command):
        return {"finding": finding, "severity": severity, "location": location,
                "tool": tool, "command": command}


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
        self.root.after(100, self._drain_queue)

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

        self._build_log_tab()
        self._build_hosts_tab()
        self._build_endpoints_tab()
        self._build_suggestions_tab()
        self._build_findings_tab()
        self._build_about_tab()

    def _build_log_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Recon Log")
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

        cols = ("severity", "finding", "location", "tool")
        self.sug_tree = ttk.Treeview(f, columns=cols, show="headings", height=14)
        widths = {"severity": 60, "finding": 300, "location": 380, "tool": 140}
        for c in cols:
            self.sug_tree.heading(c, text=c.capitalize())
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

    def _build_findings_tab(self):
        f = ttk.Frame(self.nb)
        self.nb.add(f, text="Findings Log")

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
            self.sug_tree.insert("", "end", values=(s["severity"], s["finding"], s["location"], s["tool"]),
                                  tags=(s["severity"],))
        self.sug_tree.tag_configure("P1", background="#3a1d1c")
        self.sug_tree.tag_configure("P2", background="#3a2a18")

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
        tool = parts[0]
        if not shutil.which(tool):
            messagebox.showinfo(APP_NAME, "'{}' was not found on PATH. Install it first, then use "
                                           "Copy to run it yourself, or re-try Run once it's installed.".format(tool))
            return
        self.log("[*] Running: {}".format(cmd))

        def worker():
            try:
                proc = subprocess.run(parts, capture_output=True, text=True, timeout=600)
                self.log(proc.stdout[-4000:])
                if proc.stderr:
                    self.log("[stderr] " + proc.stderr[-2000:])
            except Exception as e:
                self.log("[!] Tool run failed: {}".format(e))

        threading.Thread(target=worker, daemon=True).start()
        self.nb.select(0)

    def _suggestion_to_finding(self):
        sel = self.sug_tree.selection()
        if not sel:
            return
        idx = self.sug_tree.index(sel[0])
        s = self.recon.suggestions[idx]
        self.f_title.set(s["finding"])
        self.f_sev.set(s["severity"])
        self.f_target.set(s["location"])
        self.nb.select(4)

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
                self.sug_tree.insert("", "end", values=(s["severity"], s["finding"], s["location"], s["tool"]))
        self.project_file = path
        self.status_var.set("Project loaded from {}".format(path))


def main():
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
