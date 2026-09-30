#!/usr/bin/env python3
"""
tracker.py -- a tiny local tracker for bug bounty programs, scope, and
findings-in-progress. Backed by a single CSV file (tracker.csv) so it's
easy to open in a spreadsheet too.

Two tables, two subcommands:
  program  -- programs you're hunting (platform, scope, status)
  finding  -- findings in progress (target, class, status, payout)

-----------------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------------
  # Add a program
  python3 tracker.py program add --name "Acme Corp" --platform hackerone \\
      --scope "*.acme.com, api.acme.com" --url https://hackerone.com/acme

  # List programs
  python3 tracker.py program list

  # Add a finding
  python3 tracker.py finding add --program "Acme Corp" --target "api.acme.com" \\
      --vuln-class IDOR --status testing --notes "swapping invoice IDs across sessions"

  # Update a finding's status once submitted
  python3 tracker.py finding update --id 3 --status submitted

  # List findings, optionally filtered
  python3 tracker.py finding list --status testing
  python3 tracker.py finding list --program "Acme Corp"

  # Summary of payouts / pipeline
  python3 tracker.py summary

Finding status values (suggested, not enforced): recon, testing,
confirmed, writing_report, submitted, triaged, paid, duplicate, informative,
not_applicable.
"""

import argparse
import csv
import os
import sys
from datetime import date

PROGRAMS_CSV = "programs.csv"
FINDINGS_CSV = "findings.csv"

PROGRAM_FIELDS = ["id", "name", "platform", "url", "scope", "notes", "added_date"]
FINDING_FIELDS = ["id", "program", "target", "vuln_class", "status", "severity",
                   "payout", "notes", "added_date", "updated_date"]


def _read(path, fields):
    if not os.path.exists(path):
        return []
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _write(path, fields, rows):
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)


def _next_id(rows):
    if not rows:
        return 1
    return max(int(r["id"]) for r in rows) + 1


def program_add(args):
    rows = _read(PROGRAMS_CSV, PROGRAM_FIELDS)
    row = {
        "id": _next_id(rows),
        "name": args.name,
        "platform": args.platform or "",
        "url": args.url or "",
        "scope": args.scope or "",
        "notes": args.notes or "",
        "added_date": date.today().isoformat(),
    }
    rows.append(row)
    _write(PROGRAMS_CSV, PROGRAM_FIELDS, rows)
    print(f"[+] Added program #{row['id']}: {row['name']}")


def program_list(args):
    rows = _read(PROGRAMS_CSV, PROGRAM_FIELDS)
    if not rows:
        print("No programs tracked yet. Add one with: tracker.py program add ...")
        return
    for r in rows:
        print(f"#{r['id']} {r['name']} [{r['platform']}]")
        print(f"    url:   {r['url']}")
        print(f"    scope: {r['scope']}")
        if r["notes"]:
            print(f"    notes: {r['notes']}")
        print()


def finding_add(args):
    rows = _read(FINDINGS_CSV, FINDING_FIELDS)
    today = date.today().isoformat()
    row = {
        "id": _next_id(rows),
        "program": args.program,
        "target": args.target,
        "vuln_class": args.vuln_class or "",
        "status": args.status or "recon",
        "severity": args.severity or "",
        "payout": args.payout or "",
        "notes": args.notes or "",
        "added_date": today,
        "updated_date": today,
    }
    rows.append(row)
    _write(FINDINGS_CSV, FINDING_FIELDS, rows)
    print(f"[+] Added finding #{row['id']}: {row['target']} ({row['vuln_class']}) [{row['status']}]")


def finding_update(args):
    rows = _read(FINDINGS_CSV, FINDING_FIELDS)
    found = False
    for r in rows:
        if r["id"] == str(args.id):
            found = True
            if args.status:
                r["status"] = args.status
            if args.severity:
                r["severity"] = args.severity
            if args.payout:
                r["payout"] = args.payout
            if args.notes:
                r["notes"] = args.notes
            r["updated_date"] = date.today().isoformat()
    if not found:
        print(f"[!] No finding with id {args.id}")
        sys.exit(1)
    _write(FINDINGS_CSV, FINDING_FIELDS, rows)
    print(f"[*] Updated finding #{args.id}")


def finding_list(args):
    rows = _read(FINDINGS_CSV, FINDING_FIELDS)
    if args.status:
        rows = [r for r in rows if r["status"] == args.status]
    if args.program:
        rows = [r for r in rows if r["program"] == args.program]
    if not rows:
        print("No matching findings.")
        return
    for r in rows:
        payout = f" -- ${r['payout']}" if r["payout"] else ""
        print(f"#{r['id']} [{r['status']}] {r['target']} :: {r['vuln_class']} "
              f"({r['severity']}) [{r['program']}]{payout}")
        if r["notes"]:
            print(f"    notes: {r['notes']}")


def summary(args):
    rows = _read(FINDINGS_CSV, FINDING_FIELDS)
    if not rows:
        print("No findings tracked yet.")
        return

    by_status = {}
    total_paid = 0.0
    for r in rows:
        by_status.setdefault(r["status"], 0)
        by_status[r["status"]] += 1
        if r["status"] == "paid" and r["payout"]:
            try:
                total_paid += float(r["payout"])
            except ValueError:
                pass

    print("=== Pipeline summary ===")
    for status, count in sorted(by_status.items()):
        print(f"  {status:16s}: {count}")
    print(f"\n  Total findings tracked: {len(rows)}")
    print(f"  Total paid (confirmed): ${total_paid:.2f}")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_program = sub.add_parser("program")
    prog_sub = p_program.add_subparsers(dest="action", required=True)

    pa = prog_sub.add_parser("add")
    pa.add_argument("--name", required=True)
    pa.add_argument("--platform")
    pa.add_argument("--url")
    pa.add_argument("--scope")
    pa.add_argument("--notes")
    pa.set_defaults(func=program_add)

    pl = prog_sub.add_parser("list")
    pl.set_defaults(func=program_list)

    p_finding = sub.add_parser("finding")
    find_sub = p_finding.add_subparsers(dest="action", required=True)

    fa = find_sub.add_parser("add")
    fa.add_argument("--program", required=True)
    fa.add_argument("--target", required=True)
    fa.add_argument("--vuln-class")
    fa.add_argument("--status", default="recon")
    fa.add_argument("--severity")
    fa.add_argument("--payout")
    fa.add_argument("--notes")
    fa.set_defaults(func=finding_add)

    fu = find_sub.add_parser("update")
    fu.add_argument("--id", required=True, type=int)
    fu.add_argument("--status")
    fu.add_argument("--severity")
    fu.add_argument("--payout")
    fu.add_argument("--notes")
    fu.set_defaults(func=finding_update)

    fl = find_sub.add_parser("list")
    fl.add_argument("--status")
    fl.add_argument("--program")
    fl.set_defaults(func=finding_list)

    s = sub.add_parser("summary")
    s.set_defaults(func=summary)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
