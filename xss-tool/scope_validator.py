#!/usr/bin/env python3
"""
Scope validator for bug bounty targets.

Given a JSON scope definition (in-scope / out-of-scope patterns copied from
a program's published policy) and a candidate URL, decides whether that URL
may be tested. This is a hard gate: the XSS scanner in this tool refuses to
run against any target that does not pass validation here.

Scope patterns support:
  - exact domains:      example.com
  - subdomain wildcards: *.example.com
  - path prefixes:      app.example.com/api/*
"""
import argparse
import json
import re
import sys
from dataclasses import dataclass
from urllib.parse import urlparse


@dataclass
class ScopeResult:
    in_scope: bool
    reason: str


def _pattern_to_regex(pattern: str) -> re.Pattern:
    host_part, _, path_part = pattern.partition("/")
    host_re = re.escape(host_part).replace(r"\*", "[^/]+")
    if path_part or pattern.endswith("/"):
        path_re = re.escape(path_part).replace(r"\*", ".*")
        full = rf"^{host_re}/{path_re}$" if path_part else rf"^{host_re}/.*$"
    else:
        full = rf"^{host_re}$"
    return re.compile(full, re.IGNORECASE)


def _host_and_path(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    return f"{host}{path}"


def _matches_any(target: str, patterns: list) -> str | None:
    target_host = urlparse(target if "://" in target else f"https://{target}").hostname or ""
    target_host = target_host.lower()
    target_full = _host_and_path(target)
    for pattern in patterns:
        pattern = pattern.strip()
        if not pattern:
            continue
        regex = _pattern_to_regex(pattern)
        if regex.match(target_host) or regex.match(target_full):
            return pattern
    return None


def load_scope(scope_path: str) -> dict:
    with open(scope_path, "r") as f:
        scope = json.load(f)
    scope.setdefault("in_scope", [])
    scope.setdefault("out_of_scope", [])
    return scope


def check_scope(target_url: str, scope: dict) -> ScopeResult:
    out_match = _matches_any(target_url, scope.get("out_of_scope", []))
    if out_match:
        return ScopeResult(False, f"Target matches out-of-scope pattern: '{out_match}'")

    in_match = _matches_any(target_url, scope.get("in_scope", []))
    if in_match:
        return ScopeResult(True, f"Target matches in-scope pattern: '{in_match}'")

    return ScopeResult(False, "Target does not match any published in-scope pattern")


def main():
    parser = argparse.ArgumentParser(description="Validate a target URL against a bug bounty program's published scope.")
    parser.add_argument("--scope", required=True, help="Path to scope JSON file")
    parser.add_argument("--target", required=True, help="Target URL to validate")
    args = parser.parse_args()

    scope = load_scope(args.scope)
    result = check_scope(args.target, scope)

    print(f"Program: {scope.get('program', 'unknown')}")
    print(f"Target:  {args.target}")
    print(f"Result:  {'IN SCOPE' if result.in_scope else 'NOT IN SCOPE'}")
    print(f"Reason:  {result.reason}")

    sys.exit(0 if result.in_scope else 1)


if __name__ == "__main__":
    main()
