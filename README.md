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

```
# verify the shown programs' policy links (flags rebrands & dead pages)
python3 find_unpopular_vdp.py -n 10 --no-bounty --self-managed --check-links
```

Useful flags: `--no-bounty`, `--self-managed`, `--safe-harbor`, `--with-contact`,
`--check-links`, `-n/--limit N`, `-s/--source <url-or-file>`, `--json`.

`--check-links` pings only the programs it displays, so it stays fast. A
`moved -> …` note means the program rebranded or relocated its policy (e.g.
amoCRM → Kommo), and `dead` / `blocked` flag stale or bot-protected pages.

Use the output only for authorized, good-faith research and always follow each
program's published policy and scope.
