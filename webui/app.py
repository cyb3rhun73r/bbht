#!/usr/bin/env python3
"""
app.py -- authenticated web dashboard for the bbht toolkit.

Lets you trigger scripts/quickwin_scan.sh and scripts/generate_dorks.py
against a target from a browser, and watch real-time job status / log
output via Server-Sent Events (SSE) instead of SSHing in and tailing a
terminal.

SECURITY NOTE: this dashboard can trigger network requests against
whatever target you give it. If you expose this online (not just on
your LAN/VPN), you MUST set API_TOKEN to a real secret -- anyone who
can reach this page and knows/guesses the token can run scans through
it. Put a reverse proxy with TLS in front for real internet exposure;
don't rely on this app's bare HTTP alone. See docker/README section in
the main README for the recommended setup.

Every job also requires an explicit "I confirm this target is in my
authorized scope" checkbox -- the app logs that confirmation alongside
the job, but it is still on YOU to have actually confirmed it.
"""

import json
import os
import subprocess
import threading
import time
import uuid
from collections import deque
from datetime import datetime, timezone
from functools import wraps

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

APP_ROOT = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(APP_ROOT)
SCRIPTS_DIR = os.path.join(REPO_ROOT, "scripts")
AUDIT_LOG = os.path.join(REPO_ROOT, "scripts", "dashboard_audit.log")

API_TOKEN = os.environ.get("API_TOKEN", "")

app = Flask(__name__)

# ---------------------------------------------------------------------
# In-memory job store. Fine for a single-container personal/team tool;
# jobs don't need to survive a container restart.
# ---------------------------------------------------------------------
jobs = {}
jobs_lock = threading.Lock()

ALLOWED_TOOLS = {
    "quickwin_scan": {
        "label": "quickwin_scan.sh (low-hanging-fruit sweep)",
        "cmd": lambda target: ["bash", os.path.join(SCRIPTS_DIR, "quickwin_scan.sh"), target],
    },
    "generate_dorks": {
        "label": "generate_dorks.py (Google-dorking query list)",
        "cmd": lambda target: ["python3", os.path.join(SCRIPTS_DIR, "generate_dorks.py"), target],
    },
}


def require_token(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not API_TOKEN:
            # No token configured -- only acceptable for local/LAN use.
            return f(*args, **kwargs)
        supplied = request.headers.get("X-API-Token") or request.args.get("token") or \
            (request.authorization.password if request.authorization else None)
        if supplied != API_TOKEN:
            return jsonify({"error": "unauthorized"}), 401
        return f(*args, **kwargs)
    return wrapper


def audit(entry: dict):
    entry["ts"] = datetime.now(timezone.utc).isoformat()
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def run_job(job_id: str, tool: str, target: str):
    job = jobs[job_id]
    job["status"] = "running"
    job["started_at"] = datetime.now(timezone.utc).isoformat()

    cmd = ALLOWED_TOOLS[tool]["cmd"](target)
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1, cwd=SCRIPTS_DIR,
        )
        job["pid"] = proc.pid
        for line in proc.stdout:
            with jobs_lock:
                job["log"].append(line.rstrip())
        proc.wait()
        job["returncode"] = proc.returncode
        job["status"] = "completed" if proc.returncode == 0 else "failed"
    except Exception as e:
        job["log"].append(f"[dashboard] error launching job: {e}")
        job["status"] = "failed"
    job["finished_at"] = datetime.now(timezone.utc).isoformat()


@app.route("/")
@require_token
def index():
    return render_template("index.html", tools=ALLOWED_TOOLS, token_required=bool(API_TOKEN))


@app.route("/api/jobs", methods=["GET"])
@require_token
def list_jobs():
    with jobs_lock:
        out = [
            {
                "id": j["id"], "tool": j["tool"], "target": j["target"],
                "status": j["status"], "created_at": j["created_at"],
                "started_at": j.get("started_at"), "finished_at": j.get("finished_at"),
                "returncode": j.get("returncode"),
            }
            for j in sorted(jobs.values(), key=lambda j: j["created_at"], reverse=True)
        ]
    return jsonify(out)


@app.route("/api/jobs", methods=["POST"])
@require_token
def create_job():
    data = request.get_json(force=True) or {}
    tool = data.get("tool")
    target = (data.get("target") or "").strip()
    confirmed = bool(data.get("confirm_scope"))

    if tool not in ALLOWED_TOOLS:
        return jsonify({"error": f"unknown tool, choose from {list(ALLOWED_TOOLS)}"}), 400
    if not target:
        return jsonify({"error": "target is required"}), 400
    if not confirmed:
        return jsonify({"error": "you must confirm this target is in your authorized scope"}), 400

    job_id = str(uuid.uuid4())[:8]
    job = {
        "id": job_id, "tool": tool, "target": target,
        "status": "queued", "created_at": datetime.now(timezone.utc).isoformat(),
        "log": deque(maxlen=5000),
        "scope_confirmed_by_user": True,
    }
    with jobs_lock:
        jobs[job_id] = job

    audit({"event": "job_created", "job_id": job_id, "tool": tool, "target": target,
            "scope_confirmed": True, "remote_addr": request.remote_addr})

    thread = threading.Thread(target=run_job, args=(job_id, tool, target), daemon=True)
    thread.start()

    return jsonify({"id": job_id}), 201


@app.route("/api/jobs/<job_id>/stream")
@require_token
def stream_job(job_id):
    if job_id not in jobs:
        return jsonify({"error": "not found"}), 404

    def generate():
        job = jobs[job_id]
        sent = 0
        while True:
            with jobs_lock:
                log_snapshot = list(job["log"])
                status = job["status"]
            while sent < len(log_snapshot):
                yield f"data: {json.dumps({'line': log_snapshot[sent]})}\n\n"
                sent += 1
            if status in ("completed", "failed"):
                yield f"data: {json.dumps({'status': status, 'done': True})}\n\n"
                break
            yield f"data: {json.dumps({'status': status})}\n\n"
            time.sleep(1)

    return Response(stream_with_context(generate()), mimetype="text/event-stream")


@app.route("/healthz")
def healthz():
    return jsonify({"ok": True})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    if not API_TOKEN:
        print("[!] WARNING: API_TOKEN is not set. This dashboard is UNAUTHENTICATED.")
        print("[!] Only run this way on a trusted local/LAN network, never exposed online.")
    app.run(host="0.0.0.0", port=port, threaded=True)
