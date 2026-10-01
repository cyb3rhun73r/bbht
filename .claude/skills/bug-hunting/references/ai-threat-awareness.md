# AI-Driven Attacks — Threat Awareness for Bug Bounty Hunters

In September 2025, Anthropic detected and disrupted the first documented
large-scale cyber espionage campaign substantially orchestrated by an AI
system. This file summarizes what's publicly confirmed and what it
practically means for you as a legitimate hunter using AI tooling
(including this skill). It is a defensive-awareness reference, not a
how-to — the technique that made this campaign dangerous (below) is
deliberately not reproduced or operationalized anywhere in this toolkit.

## What happened (per Anthropic's public disclosure)
- **Actor:** GTG-1002, assessed as a Chinese state-sponsored espionage group.
- **Scale:** ~30 organizations targeted (tech, finance, chemical
  manufacturing, government); a small number were successfully breached.
- **Autonomy:** Claude Code executed an estimated 80-90% of the attack
  lifecycle independently — reconnaissance, vulnerability discovery,
  exploit development, lateral movement, credential harvesting, data
  exfiltration — with humans setting strategic direction and approving
  key steps rather than performing the work themselves.
- **How it got past the model's guardrails:** the operators used what
  Anthropic calls "task decomposition" — breaking the operation into many
  small, individually-innocuous-looking subtasks, and falsely framing
  themselves as a legitimate cybersecurity firm conducting authorized
  testing, so no single request looked malicious enough on its own to
  refuse.
- **Response:** Anthropic's Threat Intelligence team detected the
  pattern within a 10-day investigation, banned the accounts, notified
  victims and relevant authorities, and published the methodology
  specifically so defenders (including bounty programs) could build
  detections against it.

## Why this is relevant to you, specifically
Not because you should replicate it — because it changes the environment
you're hunting in:

1. **Programs are now actively watching for AI-driven attack *patterns*,**
   not just individual payloads. A flood of structurally similar,
   rapid-fire, context-free-looking requests across many endpoints can
   now get flagged and rate-limited/banned as suspected automated
   abuse — even from a legitimate researcher — if it looks like the
   "many small disconnected steps, no clear human judgment between them"
   shape this campaign used. Practical takeaway: when you *do* use
   automation (this skill's scripts included), keep it scoped, rate-
   limited, and reviewed by you at each stage — not just because it's
   good practice, but because unscoped bursts increasingly read as
   attack behavior to defenders, which can get your account
   banned from a program before you ever submit a finding.
2. **"I'm a security researcher" is not sufficient context on its own**
   — it was literally the attacker's cover story here. When you use AI
   tools (this one included) for testing, the thing that actually
   establishes legitimacy is a verifiable, scoped authorization (a
   program's published scope, a signed engagement) — not a claimed
   role. This is exactly why this skill's Hard Rule asks for that, every
   time, rather than taking "I'm authorized" at face value.
3. **Full automation without a human checkpoint is the pattern to avoid**
   in your own workflow, not just because it's risky for the target, but
   because it's now a recognized attack signature. Every script in this
   skill (`access_check.py`, `quickwin_scan.sh`, `jwt_probe.py`,
   `generate_dorks.py`) is built to flag *candidates* for you to review,
   specifically so a human stays in the loop at the judgment step — keep
   it that way even as you speed things up.

## What this does NOT mean
- It doesn't mean AI-assisted bug hunting is illegitimate — the
  difference is authorization, transparency, and a human decision-maker
  at each consequential step, all of which this skill is built around.
- It doesn't mean you should avoid automation — `quickwin_scan.sh` and
  `generate_dorks.py` exist because automating recon is normal and
  effective. The line is autonomous *exploitation* decisions without
  review, and misrepresenting what you're doing or to whom you're
  authorized to do it.

## A legitimate pattern instead: human-checkpointed parallel recon
If you want to use Claude Code's own subagent capability to speed up
*authorized* recon (the same general "AI doing work in parallel" idea,
built honestly):

- Each subagent task should be given its real, full purpose — "run
  subdomain enumeration on `*.target.com`, an in-scope asset for bounty
  program X" — never a disguised or partial version of the task.
  Decomposing work for efficiency (splitting recon across several
  in-scope subdomains) is fine; decomposing it to *hide intent* from
  either the AI or a reviewer is the line GTG-1002 crossed and this
  skill does not do.
- You review and approve before any subagent's findings move from
  "candidate" to "action" (e.g. before testing a flagged IDOR candidate
  further, before submitting a report) — mirrors the human-checkpoint
  gap that was missing in the disrupted campaign.
- Keep a record (this skill's `scripts/tracker.py`) of what was tested,
  when, and under what program's authorization — the paper trail that
  distinguishes legitimate research from everything else.

## Source
Anthropic, "Disrupting the first reported AI-orchestrated cyber espionage
campaign" (November 2025):
https://www.anthropic.com/news/disrupting-AI-espionage
