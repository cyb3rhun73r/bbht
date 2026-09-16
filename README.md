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

# Cryptojacking Scanner

`cryptojacking_scanner.py` is a standalone Python detection tool for
finding unauthorized browser-based cryptocurrency miners injected into a
site's HTML/JS (e.g. Coinhive-style attacks via compromised plugins, ads,
or CDN files). It fetches page + linked script text and pattern-matches
against known miner filenames, mining-pool domains, and miner API code
signatures. It never executes or connects to anything it finds.

Usage:
```
pip install requests
python3 cryptojacking_scanner.py https://target.example
python3 cryptojacking_scanner.py -f urls.txt -o report.json
```

Only run this against sites you own or are authorized to test.
