# Choosing a Program — Where to Actually Point This Toolkit

Everything else in this skill assumes you already have a target. This
file is about picking one that gives you the best odds of a fast, paid
result — especially your first one. The wrong program (narrow scope,
heavy competition, slow/unresponsive triage) can burn weeks with nothing
to show for it, even with good technique.

## What makes a program beginner-friendly

| Signal | Why it matters | Where to check |
|---|---|---|
| **Pays for Low/Medium severity, not just Critical** | Low-hanging-fruit findings (this skill's `low-hanging-fruit.md`) are mostly Low/Medium severity — a program that only rewards Critical wastes that work. | Program's reward table on its scope page. |
| **Wide scope (`*.company.com` wildcards, many subdomains/assets)** | More surface area = more chances to find something, and wildcard scope usually means less-scrutinized subdomains exist (good for subdomain takeover, forgotten staging environments). | Scope page — look for wildcards, not just a handful of named domains. |
| **Newer program (recently launched)** | Less picked-over by other hunters — the "low-hanging fruit" is more likely to still be there. | Platform usually shows a program's launch/join date or "new program" badge. |
| **Fast, responsive triage** | A program that takes months to respond delays your payout and your ability to learn from feedback. | HackerOne/Bugcrowd show average response time and resolution time stats on the program page. |
| **No/low minimum bounty threshold combined with "pays for Low"** | Confirms Low-severity findings are actually worth submitting, not just accepted-but-unpaid. | Reward table, sometimes an explicit "minimum bounty" line. |
| **Public program, not invite-only** | Invite-only programs need reputation you may not have yet. Start public, build reputation, get invited later. | Platform's public program directory. |
| **VDP (Vulnerability Disclosure Program) as a stepping stone** | VDPs don't pay cash but accept reports and build your public reputation/signal, which unlocks paid private program invites faster. | HackerOne/Bugcrowd both list VDPs separately from paid programs. |

## Red flags to deprioritize (not necessarily avoid, but don't start here)
- Program explicitly excludes common easy wins in its policy (e.g. "we
  do not accept clickjacking, missing rate limiting, or SPF/DMARC
  reports") — check the policy page before spending time on those
  classes for that specific program.
- Very narrow scope (one or two named domains, no wildcards) on a
  long-running, heavily-hunted program — the obvious bugs are likely
  long gone.
- History of frequent "duplicate" or "informative" closures reported by
  other hunters in community writeups — a sign of either a very
  hardened target or an overly strict triager; either way, harder for a
  first win.
- No published average response time, or a visibly very slow one (weeks
  to first response) — fine once you have a pipeline of multiple
  programs going, frustrating as your only active program early on.

## A practical first-week plan
1. Pick 2-3 public programs meeting the "beginner-friendly" signals
   above — don't commit to just one, so a slow or picked-over program
   doesn't stall you entirely.
2. Register them with `scripts/tracker.py program add` so you're not
   relying on memory once you're juggling more than one.
3. Run `scripts/quickwin_scan.sh` against each program's in-scope
   wildcard domains (confirm scope first — see the Hard Rule in
   `SKILL.md`) and work through `low-hanging-fruit.md`.
4. Once low-hanging fruit is exhausted on those, move to the deeper
   classes (`idor-bola-patterns.md`, etc.) on whichever program's scope
   felt richest/least-hunted.
5. Track every candidate and submission in `scripts/tracker.py finding`
   so you can see your pipeline and learn which programs/classes are
   actually converting to paid findings for you — that data should
   drive which programs you spend more time on next.

## A note on income expectations
Be realistic, especially early: most new hunters submit several reports
before their first paid one, and "duplicate" or "informative" closures
are a normal, expected part of the process, not a sign you're doing
something wrong. Picking programs well (this file) and picking bug
classes well (the rest of this skill) both improve your odds, but bug
bounty income is inherently variable — don't treat it as guaranteed or
predictable income for financial planning purposes.
