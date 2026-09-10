# BBHT

Bug Bounty Hunting Tools is a script to install the most popular tools used while looking for vulnerabilities for a bug bounty program.
 
# Tools

- dirsearch
- JSParser
- knockpy
- lazys3
- recon_profile
- sqlmap-dev
- Sublist3r
- teh_s3_bucketeers
- virtual-host-discovery
- wpscan
- webscreenshot
- Massdns
- Asnlookup
- Unfurl
- Waybackurls
- Httprobe
- Seclists collection

This script also grabs the aliases created and published here:
https://github.com/nahamsec/recon_profile


# Installing
- git clone https://github.com/nahamsec/bbht.git
- cd bbht
- chmod +x install.sh
- ./install.sh

# BBHT Web (iPhone-friendly scanner)

`backend/` and `frontend/` contain a self-hosted web app version of BBHT: an
automated OWASP Top 10 recon/vulnerability scanner with a mobile-first UI you
can run from Safari on an iPhone (installable as a home-screen PWA). The
original `install.sh` toolset above still targets Linux; this web app is the
iPhone-accessible alternative.

**Only scan systems you own or are explicitly authorized to test** (e.g.
in-scope assets of a bug bounty program you're enrolled in). Every target
must be marked authorized before a scan can run.

## What it does

- **Recon**: subdomain enumeration (crt.sh + DNS) with live-host probing
- **Port scan**: common TCP ports, flags risky exposed services
- **A05 Security Misconfiguration**: missing security headers, TRACE method,
  directory listing, server/version banner disclosure
- **A02 Sensitive Data Exposure**: exposed `.env`, `.git`, backups, cloud
  credentials, actuator/debug endpoints, etc.
- **A03 Injection**: error-based & boolean-based SQL injection probing,
  reflected XSS probing with unique markers — each confirmed finding
  includes a working proof-of-concept URL
- **A06 Vulnerable Components**: detects common JS library versions and
  checks them against the OSV.dev vulnerability database
- **A01 Broken Access Control**: IDOR heuristic (adjacent-ID diffing), open
  redirect detection
- **A10 SSRF**: passive SSRF probing via common parameter names
- A checklist of OWASP categories (Insecure Design, Software/Data Integrity
  Failures, Logging Failures) that can't be black-box automated, so you
  don't forget to review them manually

All active checks use safe, non-destructive payloads (no data exfiltration,
no destructive SQL, no real SSRF callbacks) — good enough to prove a finding
for a bug bounty report, not to actually exploit it further.

## Running it (Docker)

```bash
docker compose up -d --build
```

The app listens on port 8000. From your iPhone (same WiFi network, or over
a domain you expose via reverse proxy/Tailscale/Cloudflare Tunnel):

1. Open `http://<server-ip-or-domain>:8000` in Safari
2. Tap the Share icon → **Add to Home Screen** to install it as an app icon
3. Add a target, confirm authorization, then run a scan against a specific
   URL (include query parameters for the injection modules to test)

For HTTPS (recommended if exposing beyond your home network), put a reverse
proxy like Caddy or nginx with a TLS cert in front of the container, or use
a tunnel such as Cloudflare Tunnel / Tailscale Funnel.

## Running it without Docker

```bash
cd backend
pip install -r requirements.txt
DB_PATH=./bbht.db uvicorn app.main:app --host 0.0.0.0 --port 8000
```
