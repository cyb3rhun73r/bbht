# BBHT — Bug Bounty Hunting Workspace

Claude Code is configured here with the [Agentic Bug Hunter](https://github.com/awarexone/Agentic-Bug-Hunter) toolkit
(skills, slash commands, agents, rules vendored under `.claude/`), alongside the classic recon tool installer (`install.sh`).

## Ground rules (always)
- **Scope first.** Only test assets explicitly in scope for a program you are authorized on. Run `/scope <asset>` before touching anything.
- Respect program rules: rate limits, no DoS, no social engineering, no data exfiltration beyond minimal proof.
- Validate before reporting (`/validate`, 7-Question Gate). No theoretical findings.
- Never commit findings, recon output, reports, tokens, or API keys (see `.gitignore`).
- Follow `.claude/rules/hunting.md` and `.claude/rules/reporting.md`.

## Workflow
`/scope` -> `/recon target.com` -> `/surface` -> `/hunt target.com` -> `/validate` -> `/chain` -> `/report`
Resume a prior hunt with `/pickup target.com`; log leads with `/remember`.

## Layout
- `.claude/skills/`   domain skills (web2-recon, web2-vuln-classes, triage-validation, report-writing, web3-audit, ...)
- `.claude/commands/` slash commands (`/recon`, `/hunt`, `/validate`, `/report`, ...)
- `.claude/agents/`   subagents (recon-agent, validator, report-writer, chain-builder, ...)
- `.claude/rules/`    hunting + reporting rules
- `config.example.json` copy to `config.json` (gitignored) and add API keys
- `findings/ recon/ reports/` working output (gitignored)

## Tooling
`./install.sh` installs the classic recon tools into `~/tools`. For ProjectDiscovery tools used by the
toolkit (subfinder, httpx, nuclei, katana, ffuf), see `install_tools.sh` in the upstream repo.
Upstream also ships a standalone `bughunter` CLI: `uv tool install agentic-bug-hunter && bughunter setup`.

Refresh the vendored toolkit by re-copying `skills/`, `commands/`, `bughunter/agents/`, `rules/` from upstream.
