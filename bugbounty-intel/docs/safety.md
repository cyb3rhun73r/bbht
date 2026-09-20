# Safety model

`bugbounty-intel` is a research and payload-intelligence tool for **authorized**
security testing (bug bounty programs, labs, and infrastructure you own).
It is not an autonomous scanner or exploit framework.

## Request modes

| Mode | Behavior |
|---|---|
| `PASSIVE` (default) | No active requests are sent to any target. This is the default whenever `scope.yaml` is absent. |
| `SAFE_ACTIVE` | Only payloads tagged `safe_for_automation: true` (risk `SAFE`/`LOW`, non-destructive, no credential access, no exfiltration) may be sent, and only against a domain listed in `scope.yaml`'s `allowed_domains`. |
| `MANUAL` | The tool displays a payload and instructions; it never executes it. |

See `src/safety/scope.py` for the enforcement code.

## Risk levels (§9 of the project spec)

- **SAFE** - unique reflection markers, mathematical SSTI expressions, benign XSS PoCs, controlled OAST callbacks, non-sensitive authorization checks.
- **LOW** - may change application state but is normally reversible.
- **MEDIUM** - can access internal resources or cause significant processing.
- **HIGH** - can access sensitive data, execute commands, change accounts, or modify state.
- **RESTRICTED** - credential theft, session/token extraction, destructive SQL, filesystem deletion, persistence, reverse shells, malware, mass data extraction, real-user data harvesting. These are stored **as reference only**, require explicit manual review, and this tool never executes them automatically.

## What this tool will never do

- Fabricate HackerOne report data, payloads, bounty amounts, or disclosure dates (§38).
- Attack a target outside a configured `scope.yaml`.
- Auto-execute a `RESTRICTED` payload.
- Hardcode an OAST callback domain - you always supply your own.
- Present publicly-disclosed HackerOne data as private, or vice versa.

## Your responsibility

You are responsible for verifying you have explicit written authorization
before using `SAFE_ACTIVE` mode against any target, and for following the
specific bug bounty program's or engagement's rules of engagement.
