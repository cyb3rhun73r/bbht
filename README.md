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

# Finding unpopular disclosure programs

`find_unpopular_vdp.py` surfaces lesser-known, low-competition vulnerability
disclosure programs (VDPs) — self-managed programs that usually have no cash
bounty and aren't hosted on the crowded platforms, so they draw far fewer
hunters. Data comes from the public [disclose.io](https://github.com/disclose/diodb)
directory. Standard library only, no dependencies.

```
# top 25 least-crowded programs
python3 find_unpopular_vdp.py

# no-bounty, self-managed, with safe harbour, JSON output
python3 find_unpopular_vdp.py --no-bounty --self-managed --safe-harbor --json
```

Useful flags: `--no-bounty`, `--self-managed`, `--safe-harbor`, `--with-contact`,
`-n/--limit N`, `-s/--source <url-or-file>`, `--json`.

Use the output only for authorized, good-faith research and always follow each
program's published policy and scope.
