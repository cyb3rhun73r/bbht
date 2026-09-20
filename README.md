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

# Bug Hunt HQ (web app)

`bughunthq/` also ships a recon/triage tool (parameter fingerprinting, OWASP/MITRE-tagged
suggestions, one-click tool runs against sqlmap/nuclei/dalfox/wpscan/etc). It's available as
a desktop GUI (`python bughunthq/bughunthq.py`) or as a Dockerized web app:

```
docker compose up --build
```

Then open http://127.0.0.1:8000. See `bughunthq/web/app.py` for the API and
`Dockerfile`/`docker-compose.yml` for the image.

**Authorized security testing only.** The web app requires you to explicitly confirm
authorization before it will start a recon job or run any tool, and it can actively execute
tools (sqlmap, nuclei, wpscan, ...) against whatever target you give it - only run it against
targets you have explicit written permission to test (bug bounty / pentest scope, a CTF box,
or infrastructure you own), and keep the container off public interfaces (the compose file
binds it to `127.0.0.1` by default).
