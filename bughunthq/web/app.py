#!/usr/bin/env python3
"""
Bug Hunt HQ - web front end.

Same recon/triage engine as the desktop app (bughunthq.Recon), exposed over
HTTP + WebSockets instead of Tkinter, so it can run inside a container and be
driven from a browser.

Authorized security testing only. Every recon job and every tool run must be
explicitly marked as authorized by the caller - see AUTHORIZATION NOTICE
below. Do not point this at a target you do not have explicit written
permission to test.
"""
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from bughunthq.bughunthq import (
    Recon,
    child_env,
    resolve_tool_argv,
)

# Ordered scan phases, used to drive the live progress indicator in the UI.
PHASES = ["subdomains", "crawl", "params", "suggestions", "done"]

# bugbounty-intel's payload database (see bugbounty-intel/README.md). Read
# directly as plain SQLite rather than importing that project's package, so
# the two tools stay decoupled - this app degrades gracefully (empty
# results) if the database isn't present or bugbounty-intel was never synced.
INTEL_DB_PATH = os.environ.get(
    "BBINTEL_DB", str(Path.home() / ".bugbounty-intel" / "data.sqlite3")
)

# Maps a substring of a Recon suggestion's "finding" text to the matching
# bugbounty-intel payload category. Checked in order - first match wins.
FINDING_TO_INTEL_CATEGORY = [
    ("sqli candidate", "sqli"),
    ("reflected parameter", "xss"),
    ("os command-injection", "command-injection"),
    ("lfi/path-traversal", "path-traversal"),
    ("ssrf candidate", "ssrf"),
    ("ssti confirmed", "ssti"),
    ("crlf", "crlf"),
    ("open redirect", "open-redirect"),
    ("permissive cors", "cors"),
    ("graphql", "graphql"),
    ("mass-assignment", "hpp"),
]


def _intel_category_for_finding(finding_text):
    lowered = finding_text.lower()
    for substr, category in FINDING_TO_INTEL_CATEGORY:
        if substr in lowered:
            return category
    return None


def intel_lookup(category, limit=8):
    """Returns up to `limit` SAFE/LOW-risk payloads for a bugbounty-intel
    category, each with its source provenance. Never returns MEDIUM/HIGH/
    RESTRICTED payloads here - this is a suggestion surface, not an
    execution path (see bugbounty-intel/docs/safety.md)."""
    if not os.path.isfile(INTEL_DB_PATH):
        return []
    try:
        conn = sqlite3.connect(INTEL_DB_PATH)
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            """SELECT p.payload, p.purpose, p.risk_level, p.expected_indicator,
                      p.owasp, p.cwe, v.source_id, v.source_url
               FROM payloads p
               LEFT JOIN payload_variants v ON v.payload_id = p.id
               WHERE p.category = ? AND p.risk_level IN ('SAFE', 'LOW')
               GROUP BY p.id
               ORDER BY p.risk_level, p.payload
               LIMIT ?""",
            (category, limit),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except sqlite3.Error:
        return []

app = FastAPI(title="Bug Hunt HQ")

STATIC_DIR = Path(__file__).resolve().parent / "static"

# Tools this instance is willing to execute. Anything not in this set is
# refused outright, even if resolve_tool_argv() could find it on PATH - this
# keeps the web surface to the recon toolset it ships with, rather than
# letting a client shell out to an arbitrary PATH binary.
ALLOWED_TOOLS = {
    "sqlmap", "dalfox", "commix", "ffuf", "corsy", "tlsx", "nuclei",
    "wpscan", "git-dumper", "trivy", "jwt_tool", "interactsh-client",
    "subfinder", "amass", "curl",
    "httpx", "katana", "gau", "arjun",
}

TOOL_TIMEOUT_SECONDS = int(os.environ.get("BHQ_TOOL_TIMEOUT", "900"))
JOB_TTL_SECONDS = int(os.environ.get("BHQ_JOB_TTL", "3600"))

_jobs = {}
_jobs_lock = threading.Lock()


class JobCreate(BaseModel):
    domain: str
    authorized: bool
    max_subdomains: int = 100
    crawl_max_hosts: int = 5
    crawl_max_pages: int = 40
    timeout: int = 6


class ToolRun(BaseModel):
    command: str
    authorized: bool


class ValidateRequest(BaseModel):
    authorized: bool


def _new_job(domain, opts):
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "domain": domain,
        "status": "running",
        "phase": "queued",
        "created": time.time(),
        "log": [],
        "log_cond": threading.Condition(),
        "recon": None,
        "error": None,
    }
    with _jobs_lock:
        _jobs[job_id] = job

    def log_cb(msg):
        with job["log_cond"]:
            job["log"].append(str(msg))
            job["log_cond"].notify_all()

    def set_phase(phase):
        job["phase"] = phase
        log_cb("[phase] {}".format(phase))

    def worker():
        try:
            recon = Recon(domain, log_cb, opts)
            job["recon"] = recon
            set_phase("subdomains")
            recon.enumerate_subdomains()
            set_phase("crawl")
            recon.crawl_and_discover()
            set_phase("params")
            recon.test_params()
            set_phase("suggestions")
            recon.build_suggestions()
            recon.build_attack_chains()
            set_phase("done")
            job["status"] = "done"
        except Exception as e:
            job["status"] = "error"
            job["error"] = str(e)
            log_cb("[!] Job failed: {}".format(e))
        finally:
            with job["log_cond"]:
                job["log_cond"].notify_all()

    threading.Thread(target=worker, daemon=True).start()
    return job_id


def _job_or_404(job_id):
    with _jobs_lock:
        job = _jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="unknown job id")
    return job


def _job_snapshot(job):
    recon = job["recon"]
    return {
        "id": job["id"],
        "domain": job["domain"],
        "status": job["status"],
        "phase": job["phase"],
        "error": job["error"],
        "hosts": recon.subdomains if recon else [],
        "suggestions": recon.suggestions if recon else [],
        "chains": recon.chains if recon else [],
        "exposures": recon.exposures if recon else [],
        "possible_secrets": recon.possible_secrets if recon else [],
        "log_lines": len(job["log"]),
    }


@app.post("/api/jobs")
def create_job(body: JobCreate):
    domain = body.domain.strip().lower()
    if not domain or any(c in domain for c in " /\\\t\n"):
        raise HTTPException(status_code=400, detail="invalid domain")
    if not body.authorized:
        raise HTTPException(
            status_code=403,
            detail="Set authorized=true to confirm you have explicit written "
                   "permission to test this target (bug bounty / pentest scope, "
                   "CTF, or a system you own).",
        )
    opts = {
        "max_subdomains": max(1, min(body.max_subdomains, 500)),
        "crawl_max_hosts": max(1, min(body.crawl_max_hosts, 20)),
        "crawl_max_pages": max(1, min(body.crawl_max_pages, 200)),
        "timeout": max(1, min(body.timeout, 30)),
        "concurrency": 10,
        "max_js_files": 15,
        "max_param_tests": 60,
    }
    job_id = _new_job(domain, opts)
    return {"job_id": job_id}


@app.get("/api/jobs/{job_id}")
def get_job(job_id: str):
    return _job_snapshot(_job_or_404(job_id))


@app.get("/api/jobs")
def list_jobs():
    with _jobs_lock:
        return [{"id": j["id"], "domain": j["domain"], "status": j["status"],
                  "created": j["created"]} for j in _jobs.values()]


@app.websocket("/ws/jobs/{job_id}")
async def job_log_socket(ws: WebSocket, job_id: str):
    await ws.accept()
    try:
        job = _job_or_404(job_id)
    except HTTPException:
        await ws.close(code=4404)
        return

    sent = 0
    last_phase = None
    try:
        while True:
            with job["log_cond"]:
                job["log_cond"].wait(timeout=1.0)
                lines = job["log"][sent:]
                sent = len(job["log"])
            for line in lines:
                await ws.send_json({"type": "log", "line": line})
            if job["phase"] != last_phase:
                last_phase = job["phase"]
                await ws.send_json({"type": "phase", "phase": last_phase})
            if job["status"] in ("done", "error") and sent >= len(job["log"]):
                await ws.send_json({"type": "complete", "job": _job_snapshot(job)})
                break
    except WebSocketDisconnect:
        pass


@app.post("/api/jobs/{job_id}/run-tool")
async def run_tool(job_id: str, body: ToolRun):
    job = _job_or_404(job_id)
    if not body.authorized:
        raise HTTPException(status_code=403, detail="authorized must be true to run a tool")

    try:
        parts = shlex.split(body.command)
    except ValueError as e:
        raise HTTPException(status_code=400, detail="could not parse command: {}".format(e))
    if not parts:
        raise HTTPException(status_code=400, detail="empty command")

    tool, rest = parts[0], parts[1:]
    if tool not in ALLOWED_TOOLS:
        raise HTTPException(
            status_code=403,
            detail="'{}' is not in this server's allowed tool list ({})".format(
                tool, ", ".join(sorted(ALLOWED_TOOLS))),
        )
    argv = ["curl"] + rest if tool == "curl" else resolve_tool_argv(tool, rest)
    if argv is None:
        raise HTTPException(
            status_code=404,
            detail="'{}' isn't bundled in tools/ and wasn't found on PATH. Run "
                   "tools/fetch_tools.py in the image build to vendor it.".format(tool),
        )

    run_id = uuid.uuid4().hex[:12]
    run = {"id": run_id, "argv": argv, "status": "running", "log": [],
           "log_cond": threading.Condition(), "returncode": None}
    with _jobs_lock:
        job.setdefault("runs", {})[run_id] = run

    def worker():
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace",
                                     env=child_env())
            deadline = time.time() + TOOL_TIMEOUT_SECONDS
            for line in proc.stdout:
                with run["log_cond"]:
                    run["log"].append(line.rstrip("\n"))
                    run["log_cond"].notify_all()
                if time.time() > deadline:
                    proc.kill()
                    with run["log_cond"]:
                        run["log"].append("[!] killed: exceeded {}s timeout".format(TOOL_TIMEOUT_SECONDS))
                        run["log_cond"].notify_all()
                    break
            proc.wait(timeout=10)
            run["returncode"] = proc.returncode
        except Exception as e:
            with run["log_cond"]:
                run["log"].append("[!] tool run failed: {}".format(e))
                run["log_cond"].notify_all()
        finally:
            run["status"] = "done"
            with run["log_cond"]:
                run["log_cond"].notify_all()

    threading.Thread(target=worker, daemon=True).start()
    return {"run_id": run_id, "argv": argv}


@app.websocket("/ws/runs/{job_id}/{run_id}")
async def run_log_socket(ws: WebSocket, job_id: str, run_id: str):
    await ws.accept()
    job = _job_or_404(job_id)
    run = job.get("runs", {}).get(run_id)
    if run is None:
        await ws.close(code=4404)
        return
    sent = 0
    try:
        while True:
            with run["log_cond"]:
                run["log_cond"].wait(timeout=1.0)
                lines = run["log"][sent:]
                sent = len(run["log"])
            for line in lines:
                await ws.send_json({"type": "log", "line": line})
            if run["status"] == "done" and sent >= len(run["log"]):
                await ws.send_json({"type": "complete", "returncode": run["returncode"]})
                break
    except WebSocketDisconnect:
        pass


def _validate_suggestion(recon, sug):
    """Re-fires the exact PoC URL a suggestion was built from and re-checks
    the same condition that produced it, so a finding can be confirmed
    reproducible (or flagged as no longer reproducing) without eyeballing
    raw responses by hand. Covers the browser-checkable finding types the
    Recon engine itself produces (reflection, open redirect, SSTI, CRLF)."""
    finding = sug["finding"].lower()
    url = sug["location"]
    try:
        qs = parse_qs(urlsplit(url).query)
        payload = next(iter(qs.values()), [""])[0] if qs else ""

        if "reflected parameter" in finding:
            marker = next((v for v in payload.split() if v.startswith("bhq")), payload)
            r = recon._get(url)
            ok = r is not None and marker in r.text
            return {"status": "CONFIRMED" if ok else "NOT_REPRODUCIBLE"}

        if "open redirect" in finding:
            r = recon._get(url, allow_redirects=False)
            loc = r.headers.get("Location", "") if r is not None else ""
            ok = r is not None and r.status_code in (301, 302, 303, 307, 308) and "example.org" in loc
            return {"status": "CONFIRMED" if ok else "NOT_REPRODUCIBLE"}

        if "ssti confirmed" in finding:
            m = re.search(r"(\d+)\s*\*\s*(\d+)", payload)
            if not m:
                return {"status": "NOT_APPLICABLE"}
            product = str(int(m.group(1)) * int(m.group(2)))
            r = recon._get(url)
            ok = r is not None and product in r.text and payload not in r.text
            return {"status": "CONFIRMED" if ok else "NOT_REPRODUCIBLE"}

        if "crlf" in finding:
            m = re.search(r"X-Bhq-Crlf-[0-9a-z]+", payload, re.I)
            if not m:
                return {"status": "NOT_APPLICABLE"}
            r = recon._get(url)
            ok = r is not None and m.group(0).lower() in {h.lower() for h in r.headers.keys()}
            return {"status": "CONFIRMED" if ok else "NOT_REPRODUCIBLE"}
    except Exception as e:
        return {"status": "ERROR", "detail": str(e)}

    return {"status": "NOT_APPLICABLE"}


@app.post("/api/jobs/{job_id}/suggestions/{index}/validate")
def validate_suggestion_endpoint(job_id: str, index: int, body: ValidateRequest):
    job = _job_or_404(job_id)
    if not body.authorized:
        raise HTTPException(status_code=403, detail="authorized must be true to validate a finding")
    recon = job.get("recon")
    if recon is None or index < 0 or index >= len(recon.suggestions):
        raise HTTPException(status_code=404, detail="unknown suggestion index")
    return _validate_suggestion(recon, recon.suggestions[index])


@app.get("/api/jobs/{job_id}/suggestions/{index}/intel")
def suggestion_intel_endpoint(job_id: str, index: int):
    job = _job_or_404(job_id)
    recon = job.get("recon")
    if recon is None or index < 0 or index >= len(recon.suggestions):
        raise HTTPException(status_code=404, detail="unknown suggestion index")
    sug = recon.suggestions[index]
    category = _intel_category_for_finding(sug["finding"])
    if category is None:
        return {"category": None, "payloads": []}
    return {"category": category, "payloads": intel_lookup(category)}


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
