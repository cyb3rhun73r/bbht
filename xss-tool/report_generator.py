#!/usr/bin/env python3
"""
Generates a submission-ready Markdown report from a scan_result.json
produced by xss_scanner.py.
"""
import argparse
import json
from datetime import datetime, timezone

CONFIDENCE_ORDER = {"High": 0, "Medium": 1, "Low": 2}

XSS_REMEDIATION = (
    "Ensure all user-controllable input is contextually output-encoded "
    "(HTML entity encoding for HTML body context, attribute encoding for "
    "attribute context, JS string encoding for script context) before being "
    "written into the response. Consider a Content-Security-Policy as "
    "defense-in-depth."
)
REMEDIATION_BY_TYPE = {
    "Reflected XSS": XSS_REMEDIATION,
    "Reflected XSS (form)": XSS_REMEDIATION,
    "Potential DOM XSS sink": XSS_REMEDIATION,
    "Open Redirect": (
        "Validate redirect targets against a server-side allow-list of known-good "
        "paths/hosts rather than trusting a user-supplied URL. If external redirects "
        "are required, use an indirection token mapped server-side instead of "
        "accepting a raw destination URL."
    ),
    "Possible client-side/meta redirect": (
        "Confirm in a browser whether this is a real open redirect (meta-refresh or "
        "JS-based). If so, apply the same server-side allow-list validation as for "
        "HTTP-level open redirects."
    ),
    "Possible missing CSRF protection": (
        "Add a per-session, unpredictable anti-CSRF token to all state-changing "
        "(POST/PUT/DELETE) forms and validate it server-side, or confirm an "
        "equivalent protection (e.g. SameSite=Strict/Lax cookies plus origin "
        "checking) is already in place."
    ),
    "Sensitive-looking path linked without visible auth check": (
        "Confirm the linked resource enforces server-side authorization for every "
        "request (not just hiding the link in the UI). Add access-control checks "
        "if the resource is reachable by an unauthorized or unauthenticated user."
    ),
}
DEFAULT_REMEDIATION = (
    "Review the affected functionality manually to confirm impact and determine "
    "appropriate remediation."
)


def render_report(result: dict) -> str:
    findings = sorted(result.get("findings", []), key=lambda f: CONFIDENCE_ORDER.get(f["confidence"], 9))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# Security Assessment Report")
    lines.append("")
    lines.append(f"**Program:** {result.get('program', 'unknown')}  ")
    lines.append(f"**Target:** {result.get('target')}  ")
    lines.append(f"**Pages crawled:** {result.get('pages_crawled')}  ")
    lines.append(f"**Generated:** {generated}  ")
    lines.append("")
    lines.append(
        "> This report covers a single, scope-validated target tested under "
        "explicit researcher authorization. All findings require manual "
        "verification before submission -- confidence levels are heuristic, "
        "not proof of exploitability."
    )
    lines.append("")

    if not findings:
        lines.append("## Summary")
        lines.append("")
        lines.append("No indicators of the tested vulnerability classes were identified during this scan.")
        return "\n".join(lines)

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for f in findings:
        counts[f["confidence"]] = counts.get(f["confidence"], 0) + 1

    lines.append("## Summary")
    lines.append("")
    lines.append(f"- High confidence: {counts.get('High', 0)}")
    lines.append(f"- Medium confidence: {counts.get('Medium', 0)}")
    lines.append(f"- Low confidence: {counts.get('Low', 0)}")
    lines.append("")
    lines.append("## Findings")
    lines.append("")

    for i, f in enumerate(findings, 1):
        lines.append(f"### {i}. {f['type']} - {f['confidence']} confidence")
        lines.append("")
        lines.append(f"- **URL:** `{f['url']}`")
        lines.append(f"- **Parameter:** `{f['parameter']}`")
        lines.append(f"- **Payload:** `{f['payload']}`")
        lines.append(f"- **Evidence:**")
        lines.append("")
        lines.append("```")
        lines.append(f["evidence"])
        lines.append("```")
        if f.get("notes"):
            lines.append("")
            lines.append(f"**Notes:** {f['notes']}")
        lines.append("")
        remediation = REMEDIATION_BY_TYPE.get(f["type"], DEFAULT_REMEDIATION)
        lines.append(f"**Suggested remediation:** {remediation}")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Generate a Markdown report from a scan_result.json")
    parser.add_argument("--result", required=True, help="Path to scan_result.json")
    parser.add_argument("--out", default="report.md", help="Output Markdown path")
    args = parser.parse_args()

    with open(args.result) as f:
        result = json.load(f)

    report = render_report(result)
    with open(args.out, "w") as f:
        f.write(report)

    print(f"[*] Report written to {args.out}")


if __name__ == "__main__":
    main()
