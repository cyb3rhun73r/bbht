#!/usr/bin/env python3
"""bugbounty-intel - authorized bug-bounty research and payload-intelligence CLI.

See README.md and docs/safety.md before use.
"""
import csv
import io
import json
import sys

import click

from ..database import db
from ..normalizers.seed_loader import load_all_seeds


def _conn(ctx):
    return db.connect(ctx.obj.get("db_path"))


@click.group()
@click.option("--db-path", default=None, help="Path to the SQLite database (default: ~/.bugbounty-intel/data.sqlite3)")
@click.pass_context
def cli(ctx, db_path):
    ctx.ensure_object(dict)
    ctx.obj["db_path"] = db_path
    conn = db.connect(db_path)
    db.init_db(conn)
    conn.close()


@cli.command()
@click.option("--source", type=click.Choice(["all", "seeds", "hackerone", "payloadsallthethings"]), default="seeds")
@click.pass_context
def sync(ctx, source):
    """Load/refresh local data. 'seeds' (default) loads the curated
    data/payloads/*.json set - works fully offline. 'hackerone' requires
    HACKERONE_API_USERNAME/HACKERONE_API_TOKEN env vars (see collectors/hackerone.py).
    'payloadsallthethings' checks the upstream repo for new categories."""
    conn = _conn(ctx)
    if source in ("seeds", "all"):
        total, files = load_all_seeds(conn)
        click.echo("Loaded {} payload record(s) from {} seed file(s):".format(total, len(files)))
        for name, n in files:
            click.echo("  {} -> {} record(s)".format(name, n))

    if source in ("hackerone", "all"):
        from ..collectors import hackerone
        try:
            reports = list(hackerone.iter_reports(max_pages=1))
        except Exception as e:
            click.echo("[!] HackerOne sync failed: {}".format(e), err=True)
        else:
            for r in reports:
                db.upsert_hacktivity_report(conn, r)
            conn.commit()
            click.echo("Synced {} HackerOne Hacktivity report(s).".format(len(reports)))

    if source in ("payloadsallthethings", "all"):
        from ..collectors import payloadsallthethings as patt
        try:
            cats = patt.list_top_level_categories()
        except Exception as e:
            click.echo("[!] PayloadsAllTheThings sync failed: {}".format(e), err=True)
        else:
            click.echo("PayloadsAllTheThings has {} top-level categories. Compare against "
                       "the curated files in data/payloads/ and update by hand if new "
                       "categories/payloads are worth adding (see collectors/payloadsallthethings.py).".format(len(cats)))
            for c in cats:
                click.echo("  - {}".format(c))
    conn.close()


@cli.command()
@click.argument("term")
@click.option("--hackerone", "search_h1", is_flag=True, help="Search Hacktivity reports instead of payloads")
@click.pass_context
def search(ctx, term, search_h1):
    """Full-text search across payloads (default) or HackerOne reports (--hackerone)."""
    conn = _conn(ctx)
    like = "%{}%".format(term)
    if search_h1:
        rows = conn.execute(
            "SELECT * FROM hacktivity_reports WHERE title LIKE ? OR summary LIKE ? "
            "OR cwe LIKE ? OR owasp LIKE ? ORDER BY disclosed_at DESC",
            (like, like, like, like),
        ).fetchall()
        click.echo("HACKTIVITY RESULTS")
        click.echo("==================\n")
        if not rows:
            click.echo("(no locally-synced reports match - run 'bugbounty-intel sync --source hackerone' first)")
        for i, r in enumerate(rows, 1):
            _print_report(i, r)
    else:
        rows = conn.execute(
            "SELECT * FROM payloads WHERE payload LIKE ? OR category LIKE ? OR context LIKE ? "
            "OR owasp LIKE ? OR cwe LIKE ? ORDER BY category",
            (like, like, like, like, like),
        ).fetchall()
        for i, p in enumerate(rows, 1):
            _print_payload(i, p, conn)
        if not rows:
            click.echo("No payloads matched '{}'. Run 'bugbounty-intel sync' first.".format(term))
    conn.close()


@cli.command()
@click.argument("code")
@click.pass_context
def category(ctx, code):
    """List payloads/reports mapped to an OWASP Top 10:2025 code, e.g. A01."""
    conn = _conn(ctx)
    code = code.upper()
    payload_rows = conn.execute("SELECT * FROM payloads WHERE owasp LIKE ?", ("%{}%".format(code),)).fetchall()
    report_rows = conn.execute("SELECT * FROM hacktivity_reports WHERE owasp LIKE ?", ("%{}%".format(code),)).fetchall()
    click.echo("OWASP {}\n".format(code))
    click.echo("Payloads ({}):".format(len(payload_rows)))
    for i, p in enumerate(payload_rows, 1):
        _print_payload(i, p, conn)
    click.echo("\nHackerOne reports ({}):".format(len(report_rows)))
    for i, r in enumerate(report_rows, 1):
        _print_report(i, r)
    conn.close()


@cli.command()
@click.argument("cwe_code")
@click.pass_context
def cwe(ctx, cwe_code):
    """List payloads/reports mapped to a CWE code, e.g. CWE-79."""
    conn = _conn(ctx)
    payload_rows = conn.execute("SELECT * FROM payloads WHERE cwe LIKE ?", ("%{}%".format(cwe_code),)).fetchall()
    report_rows = conn.execute("SELECT * FROM hacktivity_reports WHERE cwe LIKE ?", ("%{}%".format(cwe_code),)).fetchall()
    click.echo("{}\n".format(cwe_code))
    for i, p in enumerate(payload_rows, 1):
        _print_payload(i, p, conn)
    for i, r in enumerate(report_rows, 1):
        _print_report(i, r)
    conn.close()


@cli.command()
@click.argument("report_id")
@click.pass_context
def report(ctx, report_id):
    """Show one HackerOne report by id, with its disclosed payload status (§24)."""
    conn = _conn(ctx)
    row = conn.execute("SELECT * FROM hacktivity_reports WHERE report_id=?", (report_id,)).fetchone()
    if not row:
        click.echo("No locally-synced report with id {}. Run 'bugbounty-intel sync --source hackerone' first.".format(report_id))
        return
    _print_report(1, row, verbose=True)
    conn.close()


@cli.command()
@click.argument("cat")
@click.pass_context
def payloads(ctx, cat):
    """List all payloads in a category, e.g. xss, sqli, ssrf."""
    conn = _conn(ctx)
    rows = conn.execute("SELECT * FROM payloads WHERE category=? ORDER BY risk_level", (cat,)).fetchall()
    click.echo("{} Payload Intelligence".format(cat.upper()))
    click.echo("=" * (len(cat) + 20) + "\n")
    for i, p in enumerate(rows, 1):
        _print_payload(i, p, conn)
    if not rows:
        click.echo("No payloads found for category '{}'. Run 'bugbounty-intel sync' first.".format(cat))
    conn.close()


@cli.command()
@click.option("--format", "fmt", type=click.Choice(["json", "csv", "markdown"]), default="json")
@click.option("--category", "cat", default=None)
@click.pass_context
def export(ctx, fmt, cat):
    """Export the payload dataset."""
    conn = _conn(ctx)
    if cat:
        rows = conn.execute("SELECT * FROM payloads WHERE category=?", (cat,)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM payloads").fetchall()
    records = [dict(r) for r in rows]

    if fmt == "json":
        click.echo(json.dumps(records, indent=2))
    elif fmt == "csv":
        buf = io.StringIO()
        if records:
            writer = csv.DictWriter(buf, fieldnames=records[0].keys())
            writer.writeheader()
            writer.writerows(records)
        click.echo(buf.getvalue())
    elif fmt == "markdown":
        for r in records:
            click.echo("### {} ({})\n".format(r["payload"], r["category"]))
            click.echo("- Risk: {}".format(r["risk_level"]))
            click.echo("- Purpose: {}".format(r["purpose"]))
            click.echo("- OWASP: {}".format(r["owasp"]))
            click.echo("- CWE: {}\n".format(r["cwe"]))
    conn.close()


@cli.group()
def export_intruder():
    """Export a category as a Burp Intruder-friendly wordlist (§43)."""


@export_intruder.command("category")
@click.argument("cat")
@click.pass_context
def export_intruder_category(ctx, cat):
    conn = _conn(ctx)
    rows = conn.execute(
        "SELECT payload FROM payloads WHERE category=? AND safe_for_automation=1", (cat,)
    ).fetchall()
    for r in rows:
        click.echo(r["payload"])
    conn.close()


def _print_payload(i, p, conn):
    click.echo("[{:03d}] {} context".format(i, (p["context"] or "?").upper()))
    click.echo("Payload:\n{}\n".format(p["payload"]))
    click.echo("Purpose:\n{}\n".format(p["purpose"]))
    click.echo("Risk:\n{}\n".format(p["risk_level"]))
    click.echo("CWE:\n{}\n".format(p["cwe"] or "-"))
    click.echo("OWASP:\n{}\n".format(p["owasp"] or "-"))
    variant = conn.execute(
        "SELECT * FROM payload_variants WHERE payload_id=? LIMIT 1", (p["id"],)
    ).fetchone()
    if variant:
        click.echo("Source:\n{}\n".format(variant["source_id"]))
        click.echo("Source URL:\n{}\n".format(variant["source_url"] or "-"))
    click.echo("-" * 40)


def _print_report(i, r, verbose=False):
    click.echo("[{}]".format(i))
    click.echo("Report: #{}".format(r["report_id"]))
    click.echo("Title: {}".format(r["title"] or "-"))
    click.echo("Severity: {}".format(r["severity"] or "-"))
    click.echo("CWE: {}".format(r["cwe"] or "-"))
    click.echo("OWASP: {}".format(r["owasp"] or "-"))
    click.echo("Bounty: {}".format("${}".format(r["bounty"]) if r["bounty"] else "not disclosed"))
    click.echo("Disclosed: {}".format(r["disclosed_at"] or "-"))
    click.echo("\nPayload:")
    pd = r["payload_disclosure"]
    click.echo({
        "directly_disclosed": "DIRECTLY DISCLOSED",
        "derived": "DERIVED (reconstructed, not the literal HackerOne payload)",
        "none": "NOT PUBLICLY DISCLOSED",
    }.get(pd, pd))
    click.echo("\nSource:\n{}\n".format(r["url"] or "-"))
    if verbose:
        click.echo("Summary:\n{}\n".format(r["summary"] or "-"))
    click.echo("PUBLICLY DISCLOSED")
    click.echo("-" * 40)


def main():
    cli(obj={})


if __name__ == "__main__":
    main()
