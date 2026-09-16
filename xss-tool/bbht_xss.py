#!/usr/bin/env python3
"""
Orchestrator: validate scope -> scan single authorized target -> generate report.

Usage:
    python bbht_xss.py \
        --scope example_scope.json \
        --target https://app.example.com/search?q=test \
        --confirm-authorized

This never selects a target for you and never touches more than the one
URL/domain you pass in. If the target fails the scope check, nothing is
sent to it.
"""
import argparse
import sys

from scope_validator import load_scope, check_scope
from xss_scanner import scan
from report_generator import render_report


def main():
    parser = argparse.ArgumentParser(description="Scope-gated single-target XSS assessment pipeline.")
    parser.add_argument("--scope", required=True, help="Path to scope JSON file")
    parser.add_argument("--target", required=True, help="Single target URL you are authorized to test")
    parser.add_argument("--max-pages", type=int, default=25)
    parser.add_argument("--delay", type=float, default=0.5)
    parser.add_argument(
        "--confirm-authorized",
        action="store_true",
        help="Required: attest you are personally authorized to test this target",
    )
    parser.add_argument(
        "--categories",
        default="xss,open_redirect,csrf,access_control",
        help="Comma-separated subset of: xss,open_redirect,csrf,access_control",
    )
    parser.add_argument("--out-json", default="scan_result.json")
    parser.add_argument("--out-report", default="report.md")
    args = parser.parse_args()
    categories = {c.strip() for c in args.categories.split(",") if c.strip()}

    scope = load_scope(args.scope)
    result = check_scope(args.target, scope)
    print(f"[1/3] Scope validation: {'PASS' if result.in_scope else 'FAIL'} - {result.reason}")
    if not result.in_scope:
        sys.exit(1)

    if not args.confirm_authorized:
        print("[ABORT] Pass --confirm-authorized to proceed past scope validation.", file=sys.stderr)
        sys.exit(1)

    print("[2/3] Running scan...")
    scan_result = scan(args.target, args.scope, args.max_pages, args.delay, args.confirm_authorized, categories)

    import json
    from dataclasses import asdict
    with open(args.out_json, "w") as f:
        json.dump(asdict(scan_result), f, indent=2)

    print(f"[3/3] Generating report ({len(scan_result.findings)} finding(s))...")
    report = render_report(asdict(scan_result))
    with open(args.out_report, "w") as f:
        f.write(report)

    print(f"Done. JSON: {args.out_json}  Report: {args.out_report}")


if __name__ == "__main__":
    main()
