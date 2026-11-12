# gmail-osint

Passive OSINT on a Gmail address using public sources only. Standard library, Python 3.8+.

    ./gmail_osint.py target@gmail.com
    ./gmail_osint.py -f emails.txt -j -o out.json
    ./gmail_osint.py target@gmail.com -m normalize,gravatar,github
    HIBP_API_KEY=... ./gmail_osint.py target@gmail.com -m hibp

| Module | What it does |
|---|---|
| normalize | Canonical form, +tag, googlemail.com alias (Gmail ignores dots/+tags) |
| mx | Verifies the domain's MX records via DNS-over-HTTPS |
| gravatar | Public Gravatar profile: name, location, linked accounts |
| github | Commits authored with the email, plus a same-handle user check (unauthenticated API, rate limited) |
| hibp | Breach exposure via Have I Been Pwned (needs `HIBP_API_KEY`) |

A GitHub handle match is a lead, not proof of identity. Use only on addresses you own
or are authorized to investigate.
