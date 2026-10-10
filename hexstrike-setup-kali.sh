#!/usr/bin/env bash
# Sets up HexStrike AI + bug bounty tools on Kali (WSL). Run as your normal user (uses sudo).
set -u
INSTALL_DIR="${HOME}/hexstrike-ai"

sudo apt-get update
# Install one by one so a missing package doesn't abort the rest
for p in git python3 python3-venv python3-pip python3-dev build-essential libffi-dev libssl-dev pkg-config golang-go chromium chromium-driver \
         nmap masscan sqlmap gobuster nikto dirb ffuf whatweb wafw00f amass \
         hydra john hashcat nuclei subfinder httpx-toolkit katana dnsenum theharvester \
         feroxbuster wpscan arjun dirsearch; do
  sudo apt-get install -y "$p" || echo "!! skipped $p (not in repo)"
done

# Go-based tools (fallbacks / ones Kali lacks)
export GOPATH="$HOME/go"; export PATH="$PATH:$GOPATH/bin"
grep -q 'go/bin' ~/.bashrc || echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
for p in github.com/projectdiscovery/nuclei/v3/cmd/nuclei \
         github.com/projectdiscovery/httpx/cmd/httpx \
         github.com/projectdiscovery/subfinder/v2/cmd/subfinder \
         github.com/projectdiscovery/katana/cmd/katana \
         github.com/lc/gau/v2/cmd/gau \
         github.com/tomnomnom/waybackurls@latest \
         github.com/hahwul/dalfox/v2 \
         github.com/hakluke/hakrawler; do
  case "$p" in *@*) ;; *) p="$p@latest";; esac
  command -v "$(basename "${p%@*}")" >/dev/null || go install "$p" || echo "!! go install failed: $p"
done

# HexStrike
[ -d "$INSTALL_DIR" ] || git clone https://github.com/0x4m4/hexstrike-ai.git "$INSTALL_DIR"
cd "$INSTALL_DIR"
rm -rf venv
python3 -m venv venv
if ! ./venv/bin/pip install -r requirements.txt; then
  echo "!! pip failed on system Python ($(python3 --version)); retrying with Python 3.12 via uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
  rm -rf venv && uv venv --python 3.12 venv
  uv pip install --python venv/bin/python -r requirements.txt || { echo "!! dependency install FAILED"; exit 1; }
fi

echo
echo "Done. Start the server:  cd $INSTALL_DIR && ./venv/bin/python hexstrike_server.py"
echo "MCP bridge:              ./venv/bin/python hexstrike_mcp.py --server http://localhost:8888"
