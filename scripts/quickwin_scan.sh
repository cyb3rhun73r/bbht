#!/usr/bin/env bash
#
# quickwin_scan.sh -- automates the low-hanging-fruit pass from
# .claude/skills/bug-hunting/references/low-hanging-fruit.md
#
# USE ONLY AGAINST TARGETS YOU ARE AUTHORIZED TO TEST. This script makes
# real network requests to every subdomain/endpoint it discovers. Review
# the program's scope and rate-limit rules before running it, and prefer
# running it against a short, confirmed-in-scope domain list rather than
# a whole wildcard scope on the first pass.
#
# Checks automated here:
#   1. Subdomain enumeration + live-host probing
#   2. Subdomain takeover sweep (dangling CNAME detection)
#   3. CORS misconfiguration (Origin-reflection + credentials check)
#   4. Clickjacking (missing/ineffective X-Frame-Options / CSP frame-ancestors)
#   5. Open redirect param discovery (flags candidates -- payload testing
#      still needs manual confirmation, see low-hanging-fruit.md)
#
# Everything this script flags is a CANDIDATE. Confirm manually before
# reporting -- see references/low-hanging-fruit.md for how to turn each
# flag into a verified finding and a PoC.
#
# -----------------------------------------------------------------------
# REQUIRED TOOLS (install via bbht/install.sh or manually):
#   subfinder, httpx, dnsx  (ProjectDiscovery suite)
#   curl, jq
# OPTIONAL (used if present, skipped with a note otherwise):
#   subzy        -- more thorough subdomain-takeover fingerprinting
#   nuclei       -- runs takeover + misconfig templates as a second pass
#   gau / katana -- URL collection for open-redirect param discovery
# -----------------------------------------------------------------------
#
# USAGE:
#   ./quickwin_scan.sh target.com
#   ./quickwin_scan.sh target.com --subs-file my_confirmed_subs.txt
#
set -uo pipefail

DOMAIN="${1:-}"
if [[ -z "$DOMAIN" ]]; then
    echo "Usage: $0 <domain> [--subs-file <file>]"
    exit 1
fi
shift || true

SUBS_FILE=""
if [[ "${1:-}" == "--subs-file" ]]; then
    SUBS_FILE="${2:-}"
fi

OUTDIR="quickwin_results/${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
echo "[*] Results will be saved to: $OUTDIR"
echo "[*] Target: $DOMAIN"
echo "[*] Only run this against domains you are authorized to test.
"

need() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------
# 1. Subdomain enumeration + live-host probing
# ---------------------------------------------------------------------
if [[ -n "$SUBS_FILE" && -f "$SUBS_FILE" ]]; then
    echo "[1/5] Using provided subdomain list: $SUBS_FILE"
    cp "$SUBS_FILE" "$OUTDIR/subdomains.txt"
elif need subfinder; then
    echo "[1/5] Enumerating subdomains with subfinder..."
    subfinder -d "$DOMAIN" -silent -o "$OUTDIR/subdomains.txt"
else
    echo "[1/5] subfinder not found -- skipping enumeration."
    echo "      Install it, or pass --subs-file <file> with your own list."
    echo "$DOMAIN" > "$OUTDIR/subdomains.txt"
fi

SUB_COUNT=$(wc -l < "$OUTDIR/subdomains.txt" 2>/dev/null || echo 0)
echo "      -> $SUB_COUNT subdomain(s) to check"

if need httpx; then
    echo "[*] Probing for live hosts with httpx..."
    httpx -l "$OUTDIR/subdomains.txt" -silent -o "$OUTDIR/live_hosts.txt" 2>/dev/null
else
    echo "[*] httpx not found -- treating all subdomains as https:// live hosts (best-effort)."
    sed 's~^~https://~' "$OUTDIR/subdomains.txt" > "$OUTDIR/live_hosts.txt"
fi
LIVE_COUNT=$(wc -l < "$OUTDIR/live_hosts.txt" 2>/dev/null || echo 0)
echo "      -> $LIVE_COUNT live host(s)"
echo

# ---------------------------------------------------------------------
# 2. Subdomain takeover sweep
# ---------------------------------------------------------------------
echo "[2/5] Subdomain takeover sweep..."
TAKEOVER_OUT="$OUTDIR/takeover_candidates.txt"
: > "$TAKEOVER_OUT"

# Known vulnerable-service CNAME fingerprints (service domain -> expected
# "unclaimed" signature text). Extend this list as new services surface --
# see github.com/EdOverflow/can-i-take-over-xyz for the canonical list.
declare -A FINGERPRINTS=(
    ["herokuapp.com"]="no such app"
    ["github.io"]="There isn't a GitHub Pages site here"
    ["s3.amazonaws.com"]="NoSuchBucket"
    ["azurewebsites.net"]="Web App - Unavailable"
    ["cloudapp.net"]="Web App - Unavailable"
    ["tumblr.com"]="Whatever you were looking for doesn't currently exist"
    ["wordpress.com"]="Do you want to register"
    ["shopify.com"]="Sorry, this shop is currently unavailable"
    ["fastly.net"]="Fastly error: unknown domain"
    ["pantheonsite.io"]="The gods are wise"
    ["zendesk.com"]="Help Center Closed"
    ["statuspage.io"]="You are being"
    ["cargocollective.com"]="404 Not Found"
    ["uservoice.com"]="This UserVoice subdomain is currently available"
)

if need dnsx; then
    dnsx -l "$OUTDIR/subdomains.txt" -cname -resp-only -silent > "$OUTDIR/cnames.txt" 2>/dev/null
elif command -v dig >/dev/null 2>&1; then
    : > "$OUTDIR/cnames.txt"
    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        cname=$(dig +short CNAME "$sub" 2>/dev/null | head -n1)
        [[ -n "$cname" ]] && echo "$cname" >> "$OUTDIR/cnames.txt"
    done < "$OUTDIR/subdomains.txt"
else
    echo "      Neither dnsx nor dig found -- skipping CNAME lookup."
    touch "$OUTDIR/cnames.txt"
fi

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    for svc in "${!FINGERPRINTS[@]}"; do
        if [[ "$line" == *"$svc"* ]]; then
            echo "  [?] dangling-looking CNAME -> $line (service: $svc)" | tee -a "$TAKEOVER_OUT"
        fi
    done
done < "$OUTDIR/cnames.txt"

if need subzy; then
    echo "      Running subzy for deeper fingerprint confirmation..."
    subzy run --targets "$OUTDIR/subdomains.txt" --output "$OUTDIR/subzy_results.txt" 2>/dev/null
else
    echo "      (subzy not found -- install for more thorough fingerprint matching: https://github.com/PentestPad/subzy)"
fi
echo "      -> candidates saved to $TAKEOVER_OUT"
echo "      NEXT STEP (manual): for each candidate, visit it in a browser,"
echo "      confirm the service's 'unclaimed' page, then claim the same"
echo "      name on that service yourself as PoC. See low-hanging-fruit.md."
echo

# ---------------------------------------------------------------------
# 3. CORS misconfiguration check
# ---------------------------------------------------------------------
echo "[3/5] CORS misconfiguration check..."
CORS_OUT="$OUTDIR/cors_candidates.txt"
: > "$CORS_OUT"

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    spoofed="https://evil-$(date +%s%N | tail -c 6).attacker-test.com"
    resp_headers=$(curl -s -D - -o /dev/null --max-time 8 \
        -H "Origin: $spoofed" "$host" 2>/dev/null)
    acao=$(echo "$resp_headers" | grep -i "^access-control-allow-origin:" | tr -d '\r')
    acac=$(echo "$resp_headers" | grep -i "^access-control-allow-credentials:" | tr -d '\r')

    if echo "$acao" | grep -qi "$spoofed"; then
        flag="ORIGIN_REFLECTED"
        if echo "$acac" | grep -qi "true"; then
            flag="ORIGIN_REFLECTED + CREDENTIALS_TRUE (high impact)"
        fi
        echo "  [!] $host -- $flag" | tee -a "$CORS_OUT"
        echo "      $acao" >> "$CORS_OUT"
        [[ -n "$acac" ]] && echo "      $acac" >> "$CORS_OUT"
    fi
done < "$OUTDIR/live_hosts.txt"

echo "      -> candidates saved to $CORS_OUT"
echo

# ---------------------------------------------------------------------
# 4. Clickjacking check
# ---------------------------------------------------------------------
echo "[4/5] Clickjacking header check..."
CLICKJACK_OUT="$OUTDIR/clickjacking_candidates.txt"
: > "$CLICKJACK_OUT"

while IFS= read -r host; do
    [[ -z "$host" ]] && continue
    headers=$(curl -s -D - -o /dev/null --max-time 8 "$host" 2>/dev/null)
    xfo=$(echo "$headers" | grep -i "^x-frame-options:" | tr -d '\r')
    csp=$(echo "$headers" | grep -i "^content-security-policy:" | tr -d '\r')

    if [[ -z "$xfo" ]] && ! echo "$csp" | grep -qi "frame-ancestors"; then
        echo "  [!] $host -- no X-Frame-Options and no CSP frame-ancestors" | tee -a "$CLICKJACK_OUT"
    elif echo "$xfo" | grep -qi "allow-from"; then
        echo "  [!] $host -- X-Frame-Options uses ALLOW-FROM (not enforced by Chrome/modern browsers): $xfo" | tee -a "$CLICKJACK_OUT"
    fi
done < "$OUTDIR/live_hosts.txt"

echo "      -> candidates saved to $CLICKJACK_OUT"
echo "      NOTE: only report this on sensitive/state-changing pages, not"
echo "      static marketing pages -- check program policy first."
echo

# ---------------------------------------------------------------------
# 5. Open redirect param discovery
# ---------------------------------------------------------------------
echo "[5/5] Open redirect parameter discovery..."
REDIRECT_OUT="$OUTDIR/open_redirect_candidates.txt"
: > "$REDIRECT_OUT"

REDIRECT_PARAM_REGEX='(redirect|redirect_to|redirect_uri|return|return_to|next|dest|destination|r|u|url|continue|rurl|target)='

if need gau; then
    echo "      Collecting URLs with gau..."
    gau "$DOMAIN" 2>/dev/null > "$OUTDIR/all_urls.txt"
elif need katana; then
    echo "      Collecting URLs with katana..."
    katana -u "https://$DOMAIN" -silent 2>/dev/null > "$OUTDIR/all_urls.txt"
else
    echo "      Neither gau nor katana found -- skipping URL collection."
    echo "      Install one of them for this check, or supply your own URL list."
    touch "$OUTDIR/all_urls.txt"
fi

grep -Ei "$REDIRECT_PARAM_REGEX" "$OUTDIR/all_urls.txt" 2>/dev/null | sort -u > "$REDIRECT_OUT"
CANDIDATE_COUNT=$(wc -l < "$REDIRECT_OUT" 2>/dev/null || echo 0)
echo "      -> $CANDIDATE_COUNT URL(s) with redirect-like params saved to $REDIRECT_OUT"
echo "      NEXT STEP (manual): test each with the payload list in"
echo "      low-hanging-fruit.md (protocol-relative //evil.com, @-trick,"
echo "      etc.) -- this script only finds candidates, doesn't confirm."
echo

# ---------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------
echo "======================================================================"
echo "[*] Quick-win scan complete for $DOMAIN"
echo "    Results directory: $OUTDIR"
echo
echo "    Subdomain takeover candidates : $(wc -l < "$TAKEOVER_OUT" 2>/dev/null || echo 0)"
echo "    CORS misconfig candidates     : $(grep -c '^\s*\[!\]' "$CORS_OUT" 2>/dev/null || echo 0)"
echo "    Clickjacking candidates       : $(grep -c '^\s*\[!\]' "$CLICKJACK_OUT" 2>/dev/null || echo 0)"
echo "    Open redirect param candidates: $CANDIDATE_COUNT"
echo
echo "    Every line above is a CANDIDATE, not a confirmed finding."
echo "    Work through references/low-hanging-fruit.md to verify and build"
echo "    a PoC for each before reporting."
echo "======================================================================"
