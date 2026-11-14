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

# Claude Code bug hunting setup

This repo also bundles the [Agentic Bug Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) toolkit under `.claude/`
(26 skills, 41 slash commands, agents, rules). Open Claude Code in this directory, then:

- `/scope <asset>` verify scope, `/recon target.com`, `/hunt target.com`, `/validate`, `/report`
- `cp config.example.json config.json` and add your API keys (gitignored)

Only test targets you are authorized to test. See `CLAUDE.md`.
