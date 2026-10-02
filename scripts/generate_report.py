#!/usr/bin/env python3
"""
generate_report.py -- turns your raw testing notes into a clean,
submission-ready bug bounty report (HackerOne/Bugcrowd style).

This does NOT decide whether you have a real finding -- that's still on
you, per every reference file in the bug-hunting skill ("verify before
reporting"). It just removes the friction of formatting a good writeup
once you've confirmed one, so you spend time hunting, not typing.

-----------------------------------------------------------------------------
USAGE (interactive -- just answer the prompts)
-----------------------------------------------------------------------------
  python3 generate_report.py

USAGE (from a JSON file, e.g. to script report generation)
-----------------------------------------------------------------------------
  python3 generate_report.py --from-json report_input.json --out report.md

JSON shape (all fields optional except title/vuln_class/severity):
{
  "title": "IDOR on /api/invoices/{id} allows viewing any user's invoices",
  "vuln_class": "IDOR / Broken Access Control",
  "severity": "High",
  "target": "https://app.target.com",
  "summary": "The invoice endpoint does not verify the requesting user owns the invoice ID.",
  "steps": [
    "Log in as userA, create an invoice, note its ID (e.g. 1001).",
    "Log in as userB in a second session.",
    "Send GET /api/invoices/1001 using userB's session cookie.",
    "Observe userA's invoice data is returned."
  ],
  "request": "GET /api/invoices/1001 HTTP/1.1\\nHost: app.target.com\\nCookie: session=<userB_session>\\n",
  "response": "HTTP/1.1 200 OK\\n...\\n{\\"invoice_id\\": 1001, \\"owner\\": \\"userA\\", ...}",
  "impact": "Any authenticated user can read any other user's invoices, including billing address and line items.",
  "remediation": "Verify the requesting user owns the resource before returning it, server-side, on every request.",
  "references": ["https://hackerone.com/reports/854290"]
}
"""

import argparse
import json
import sys
from datetime import date

TEMPLATE = """# {title}

**Vulnerability class:** {vuln_class}
**Severity:** {severity}
**Target:** {target}
**Date found:** {date}

## Summary
{summary}

## Steps to Reproduce
{steps}

## Proof of Concept

### Request
```
{request}
```

### Response
```
{response}
```

## Impact
{impact}

## Suggested Remediation
{remediation}
{references_section}"""


def numbered(items):
    if not items:
        return "1. (fill in reproduction steps)"
    return "\n".join(f"{i+1}. {step}" for i, step in enumerate(items))


def render(data: dict) -> str:
    refs = data.get("references") or []
    references_section = ""
    if refs:
        references_section = "\n## References\n" + "\n".join(f"- {r}" for r in refs) + "\n"

    return TEMPLATE.format(
        title=data.get("title", "(untitled finding)"),
        vuln_class=data.get("vuln_class", "(fill in)"),
        severity=data.get("severity", "(fill in: Critical/High/Medium/Low)"),
        target=data.get("target", "(fill in)"),
        date=data.get("date", date.today().isoformat()),
        summary=data.get("summary", "(one paragraph: what the bug is and why it matters)"),
        steps=numbered(data.get("steps")),
        request=data.get("request", "(paste the exact request)"),
        response=data.get("response", "(paste the exact response showing the issue)"),
        impact=data.get("impact", "(what can an attacker actually do with this?)"),
        remediation=data.get("remediation", "(how should the target fix this?)"),
        references_section=references_section,
    )


def prompt_interactive() -> dict:
    print("=== Bug Report Generator ===")
    print("(Press Enter to leave a field blank / fill in later)\n")

    data = {}
    data["title"] = input("Title (short, specific): ").strip()
    data["vuln_class"] = input("Vulnerability class (e.g. IDOR, SSRF, XSS): ").strip()
    data["severity"] = input("Severity (Critical/High/Medium/Low): ").strip()
    data["target"] = input("Target URL/asset: ").strip()
    data["summary"] = input("One-paragraph summary: ").strip()

    print("\nSteps to reproduce (one per line, blank line to finish):")
    steps = []
    while True:
        step = input(f"  {len(steps)+1}. ").strip()
        if not step:
            break
        steps.append(step)
    data["steps"] = steps

    print("\nRequest (paste, end with a blank line):")
    data["request"] = _multiline_input()

    print("Response (paste, end with a blank line):")
    data["response"] = _multiline_input()

    data["impact"] = input("\nImpact (what can an attacker do with this?): ").strip()
    data["remediation"] = input("Suggested remediation: ").strip()

    return data


def _multiline_input() -> str:
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--from-json", help="load report fields from a JSON file instead of prompting")
    ap.add_argument("--out", default=None, help="write to this file instead of stdout")
    args = ap.parse_args()

    if args.from_json:
        with open(args.from_json) as f:
            data = json.load(f)
    else:
        data = prompt_interactive()

    report = render(data)

    if args.out:
        with open(args.out, "w") as f:
            f.write(report)
        print(f"\n[*] Report written to {args.out}")
        print("[*] Review it, verify every claim is accurate, then submit.")
    else:
        print("\n" + "=" * 70)
        print(report)


if __name__ == "__main__":
    main()
