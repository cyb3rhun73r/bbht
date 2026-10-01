#!/usr/bin/env python3
"""
generate_dorks.py -- generates a categorized Google-dorking query list for
a target domain, grounded in the real disclosed-report patterns in
.claude/skills/bug-hunting/references/google-dorking-patterns.md.

This script does NOT query Google itself (automated scraping of Google's
results page violates its Terms of Service and can get an IP blocked).
It only PRINTS the queries. Run them one of two ways:

  1. Paste each into a real browser search bar yourself, or
  2. If you're using this inside Claude Code, ask it to run the queries
     for you using its own web-search tool and summarize the hits --
     that stays within normal search-API usage rather than scraping,
     and the bug-hunting SKILL.md wires this in as step 1a.

USE ONLY AGAINST TARGETS YOU ARE AUTHORIZED TO TEST. Dorking itself only
queries a public search index, but whatever you find and then click
into (an admin panel, an unsubscribe endpoint, a leaked file) is subject
to the same scope rules as everything else in this skill.

-----------------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------------
  python3 generate_dorks.py target.com
  python3 generate_dorks.py target.com --category secrets
  python3 generate_dorks.py target.com --format json
"""

import argparse
import json
import sys

CATEGORIES = {
    "secrets": {
        "label": "Exposed config / secrets files",
        "source": "general pattern + info-disclosure-patterns.md",
        "queries": [
            'site:{domain} ext:env | ext:yaml | ext:yml | ext:json | ext:xml',
            'site:{domain} filetype:sql "INSERT INTO" "VALUES"',
            'site:{domain} filetype:log intext:password',
            'site:{domain} inurl:config intext:"DB_PASSWORD" OR intext:"api_key"',
            'site:{domain} filetype:env "DB_PASSWORD"',
            'site:{domain} intext:"AKIA" (AWS access key prefix, check context before treating as a real finding)',
        ],
    },
    "admin": {
        "label": "Exposed admin / debug panels",
        "source": "low-hanging-fruit.md",
        "queries": [
            'site:{domain} inurl:admin intitle:"login"',
            'site:{domain} inurl:(wp-admin | phpmyadmin | adminer)',
            'site:{domain} inurl:actuator',
            'site:{domain} inurl:console intitle:"console"',
            'site:{domain} inurl:debug',
        ],
    },
    "endpoints": {
        "label": "Enumerable / unauthenticated action endpoints",
        "source": "Khan Academy H1 #1210043, Mars/Banfield H1 #2055081",
        "queries": [
            'site:{domain} inurl:join',
            'site:{domain} inurl:unsubscribe',
            'site:{domain} inurl:invite',
            'site:{domain} inurl:reset',
            'site:{domain} inurl:token',
            'site:{domain} inurl:confirm',
            'site:{domain} inurl:approve',
            'site:{domain} inurl:download',
        ],
    },
    "documents": {
        "label": "Exposed internal documents",
        "source": "general pattern",
        "queries": [
            'site:{domain} filetype:pdf intext:confidential',
            'site:{domain} filetype:xlsx OR filetype:docx intext:confidential',
            'site:{domain} inurl:drive.google.com OR inurl:docs.google.com',
        ],
    },
    "errors": {
        "label": "Exposed error pages / stack traces",
        "source": "general pattern",
        "queries": [
            'site:{domain} intext:"stack trace"',
            'site:{domain} intext:"fatal error"',
            'site:{domain} intext:"warning: mysql"',
        ],
    },
    "subdomains": {
        "label": "Subdomain / asset discovery via search index",
        "source": "complements subfinder/amass -- search engines sometimes index hosts those miss",
        "queries": [
            'site:{domain} -www',
            'site:*.{domain}',
        ],
    },
}


def generate(domain: str, category: str = None):
    cats = CATEGORIES if not category else {category: CATEGORIES[category]}
    result = {}
    for key, info in cats.items():
        result[key] = {
            "label": info["label"],
            "source": info["source"],
            "queries": [q.format(domain=domain) for q in info["queries"]],
        }
    return result


def print_text(result: dict, domain: str):
    print(f"=== Google dorking queries for: {domain} ===")
    print("(Run these in a browser, or ask Claude Code to run them via its")
    print(" web-search tool and summarize hits -- see SKILL.md step 1a.)\n")
    for key, info in result.items():
        print(f"## {info['label']}  [{key}]")
        print(f"   (grounded in: {info['source']})")
        for q in info["queries"]:
            print(f"   {q}")
        print()
    print("Reminder: dorking is zero-risk recon, but confirm scope before")
    print("interacting with anything you find. See google-dorking-patterns.md")
    print("for the full methodology and real disclosed examples.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("domain", help="target domain, e.g. target.com")
    ap.add_argument("--category", choices=list(CATEGORIES.keys()),
                     help="only generate this category (default: all)")
    ap.add_argument("--format", choices=["text", "json"], default="text")
    args = ap.parse_args()

    if args.category and args.category not in CATEGORIES:
        sys.exit(f"Unknown category. Choose from: {', '.join(CATEGORIES)}")

    result = generate(args.domain, args.category)

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print_text(result, args.domain)


if __name__ == "__main__":
    main()
