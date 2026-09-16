#!/usr/bin/env python3
"""
Generates a submission-ready Markdown report from a scan_result.json
produced by xss_scanner.py.
"""
import argparse
import json
from datetime import datetime, timezone

CONFIDENCE_ORDER = {"High": 0, "Medium": 1, "Low": 2}

REMEDIATION = (
    "Ensure all user-controllable input is contextually output-encoded "
    "(HTML entity encoding for HTML body context, attribute encoding for "
    "attribute context, JS string encoding for script context) before being "
    "written into the response. Consider a Content-Security-Policy as "
    "defense-in-depth."
)


def render_report(result: dict) -> str:
    findings = sorted(result.get("findings", []), key=lambda f: CONFIDENCE_ORDER.get(f["confidence"], 9))
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# XSS Assessment Report")
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
        lines.append("No XSS indicators were identified during this scan.")
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
        lines.append(f"**Suggested remediation:** {REMEDIATION}")
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
