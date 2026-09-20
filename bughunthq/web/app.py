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
import shlex
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path

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


def _new_job(domain, opts):
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "domain": domain,
        "status": "running",
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

    def worker():
        try:
            recon = Recon(domain, log_cb, opts)
            job["recon"] = recon
            recon.enumerate_subdomains()
            recon.crawl_and_discover()
            recon.test_params()
            recon.build_suggestions()
            recon.build_attack_chains()
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
    try:
        while True:
            with job["log_cond"]:
                job["log_cond"].wait(timeout=1.0)
                lines = job["log"][sent:]
                sent = len(job["log"])
            for line in lines:
                await ws.send_json({"type": "log", "line": line})
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


@app.get("/")
def index():
    return FileResponse(str(STATIC_DIR / "index.html"))


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
