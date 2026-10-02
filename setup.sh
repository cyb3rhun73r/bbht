#!/usr/bin/env bash
#
# setup.sh -- one-command setup for the bbht bug-hunting toolkit on a new
# machine. Safe to re-run (idempotent). Installs Python dependencies and
# checks for the optional recon tools quickwin_scan.sh benefits from,
# offering to install the Go-based ones if Go is available.
#
# USAGE:
#   ./setup.sh
#
set -uo pipefail

BOLD=$(tput bold 2>/dev/null || echo "")
RESET=$(tput sgr0 2>/dev/null || echo "")
GREEN=$(tput setaf 2 2>/dev/null || echo "")
YELLOW=$(tput setaf 3 2>/dev/null || echo "")

say()  { echo -e "${BOLD}==>${RESET} $*"; }
ok()   { echo -e "  ${GREEN}✓${RESET} $*"; }
warn() { echo -e "  ${YELLOW}!${RESET} $*"; }

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say "bbht bug-hunting toolkit setup"
echo

# ---------------------------------------------------------------------
# 1. Python dependencies
# ---------------------------------------------------------------------
say "Installing Python dependencies (requests, pyjwt)..."
if command -v pip3 >/dev/null 2>&1; then
    pip3 install --quiet --user requests pyjwt 2>/dev/null \
        && ok "requests, pyjwt installed" \
        || warn "pip3 install failed -- install manually: pip3 install requests pyjwt"
else
    warn "pip3 not found -- install Python 3 and pip first"
fi
echo

# ---------------------------------------------------------------------
# 2. Make scripts executable (in case git didn't preserve the bit)
# ---------------------------------------------------------------------
chmod +x "$ROOT_DIR"/scripts/*.sh "$ROOT_DIR"/scripts/*.py 2>/dev/null
ok "scripts/ made executable"
echo

# ---------------------------------------------------------------------
# 3. Check for optional recon tools used by quickwin_scan.sh
# ---------------------------------------------------------------------
say "Checking optional recon tools (used by scripts/quickwin_scan.sh)..."
declare -A TOOL_PKG=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
    ["subzy"]="github.com/PentestPad/subzy@latest"
)

MISSING=()
for tool in "${!TOOL_PKG[@]}"; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool found"
    else
        warn "$tool not found"
        MISSING+=("$tool")
    fi
done
echo

if [[ ${#MISSING[@]} -gt 0 ]]; then
    if command -v go >/dev/null 2>&1; then
        read -p "Install missing tools (${MISSING[*]}) via 'go install'? [y/N] " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            for tool in "${MISSING[@]}"; do
                say "Installing $tool..."
                go install -v "${TOOL_PKG[$tool]}" 2>&1 | tail -5
            done
            echo
            warn "Make sure \$(go env GOPATH)/bin is on your \$PATH:"
            echo "    export PATH=\$PATH:\$(go env GOPATH)/bin"
        fi
    else
        warn "Go not found -- install Go first (https://go.dev/dl/) to get these tools,"
        warn "or install them another way. quickwin_scan.sh degrades gracefully without"
        warn "them (falls back to basic curl/dig-based checks where possible)."
    fi
fi
echo

# ---------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------
say "Setup complete."
echo
echo "Next steps:"
echo "  1. In Claude Code, the bug-hunting skill (.claude/skills/bug-hunting/)"
echo "     loads automatically -- just start talking about bug bounty hunting."
echo "  2. Or run scripts directly, e.g.:"
echo "       ./scripts/generate_dorks.py <domain>"
echo "       ./scripts/quickwin_scan.sh <domain>"
echo "       ./scripts/tracker.py program add --name \"...\" --platform hackerone"
echo "  3. See scripts/README.md and .claude/skills/bug-hunting/SKILL.md for"
echo "     the full workflow."
echo
echo "Reminder: only test targets you are explicitly authorized to test."
