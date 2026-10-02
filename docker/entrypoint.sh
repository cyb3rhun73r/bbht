#!/usr/bin/env bash
# entrypoint.sh -- links persistent data into place, then starts the
# dashboard. Keeps tracker.py/quickwin_scan.sh untouched (they just write
# relative to the scripts/ directory) by symlinking their output files
# into the mounted volume, so program/finding tracking and scan results
# survive a container restart or rebuild.
set -euo pipefail

DATA_DIR="${TRACKER_DATA_DIR:-/app/scripts_data}"
mkdir -p "$DATA_DIR/quickwin_results"
touch "$DATA_DIR/programs.csv.placeholder" 2>/dev/null || true
rm -f "$DATA_DIR/programs.csv.placeholder"

cd /app/scripts

for f in programs.csv findings.csv dashboard_audit.log; do
    target="$DATA_DIR/$f"
    [ -e "$target" ] || touch "$target"
    ln -sf "$target" "$f"
done

[ -L quickwin_results ] || { rm -rf quickwin_results; ln -sf "$DATA_DIR/quickwin_results" quickwin_results; }

cd /app

if [ -z "${API_TOKEN:-}" ]; then
    echo "[!] WARNING: API_TOKEN is not set -- dashboard is UNAUTHENTICATED."
    echo "[!] Set API_TOKEN (see docker-compose.yml) before exposing this beyond localhost."
fi

echo "[*] Starting bbht dashboard on :${PORT:-8080}"
exec python3 webui/app.py
