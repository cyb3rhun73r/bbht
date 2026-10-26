#!/usr/bin/env python3
"""
access_check.py -- semi-automated IDOR / broken access control helper.

USE ONLY AGAINST TARGETS YOU ARE AUTHORIZED TO TEST (a bug bounty program's
in-scope assets, or your own lab). This tool does NOT decide what counts as
a vulnerability -- it replays requests under different sessions/IDs and
surfaces DIFFERENCES for a human to review. Every flagged result must be
manually verified before you treat it as a finding.

-----------------------------------------------------------------------------
HOW IT WORKS
-----------------------------------------------------------------------------
1. You define one or more "request templates" in a YAML/JSON config file.
   Each template is an HTTP request with a `{id}` placeholder somewhere in
   the URL, body, or headers, representing an object/resource ID you want
   to test (e.g. /api/invoices/{id}).

2. You define one or more "sessions" -- named sets of auth headers/cookies
   for accounts you control (e.g. your own low-privilege test account, a
   second test account, or "anon" for no auth at all).

3. The tool sends every template, for every session, across a range/list of
   IDs you supply, and records status code + response length + a content
   hash for each combination.

4. It then flags combinations where a session was able to retrieve a
   resource that (a) belongs to a different session's account, or
   (b) an unauthenticated/lower-priv session should plausibly not reach --
   based on you telling it which IDs "belong" to which session.

-----------------------------------------------------------------------------
CONFIG FORMAT (JSON)
-----------------------------------------------------------------------------
{
  "base_url": "https://target.example.com",
  "sessions": {
    "userA": {"headers": {"Cookie": "session=abc123"}},
    "userB": {"headers": {"Cookie": "session=def456"}},
    "anon":  {"headers": {}}
  },
  "owned_ids": {
    "userA": ["1001", "1002"],
    "userB": ["2001", "2002"]
  },
  "templates": [
    {
      "name": "get_invoice",
      "method": "GET",
      "path": "/api/invoices/{id}",
      "headers": {},
      "body": null
    }
  ],
  "id_range": ["1001", "1002", "2001", "2002"]
}

-----------------------------------------------------------------------------
USAGE
-----------------------------------------------------------------------------
  python3 access_check.py --config target_config.json --out results.json

  # then review results.json / the printed table manually.
"""

import argparse
import hashlib
import json
import sys
import time
from dataclasses import dataclass, asdict
from typing import Optional

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install requests")


@dataclass
class ProbeResult:
    template: str
    session: str
    id_tested: str
    method: str
    url: str
    status: int
    length: int
    content_hash: str
    owned_by: Optional[str]
    flag: str  # "", "CROSS_ACCOUNT_ACCESS", "UNAUTH_ACCESS", "ERROR"


def load_config(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def fill(template_str: str, obj_id: str) -> str:
    return template_str.replace("{id}", obj_id)


def owner_of(owned_ids: dict, obj_id: str) -> Optional[str]:
    for owner, ids in owned_ids.items():
        if obj_id in ids:
            return owner
    return None


def probe(base_url, session_name, session_cfg, template, obj_id, owned_ids,
          delay: float, timeout: float) -> ProbeResult:
    method = template.get("method", "GET").upper()
    path = fill(template["path"], obj_id)
    url = base_url.rstrip("/") + path
    headers = dict(template.get("headers") or {})
    headers.update(session_cfg.get("headers") or {})
    body = template.get("body")
    if isinstance(body, str):
        body = fill(body, obj_id)

    owner = owner_of(owned_ids, obj_id)
    flag = ""

    try:
        resp = requests.request(method, url, headers=headers,
                                 data=body, timeout=timeout,
                                 allow_redirects=False)
        content_hash = hashlib.sha256(resp.content).hexdigest()[:12]
        length = len(resp.content)
        status = resp.status_code

        # Heuristic flagging -- REVIEW MANUALLY, these are hints not proof.
        success_like = status in (200, 201, 202, 203, 206)
        if success_like and owner is not None and owner != session_name:
            flag = "CROSS_ACCOUNT_ACCESS"
        elif success_like and session_name == "anon" and owner is not None:
            flag = "UNAUTH_ACCESS"

    except requests.RequestException as e:
        status = -1
        length = 0
        content_hash = ""
        flag = "ERROR"

    if delay:
        time.sleep(delay)

    return ProbeResult(
        template=template["name"], session=session_name, id_tested=obj_id,
        method=method, url=url, status=status, length=length,
        content_hash=content_hash, owned_by=owner, flag=flag,
    )


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--config", required=True, help="JSON config file (see script docstring)")
    ap.add_argument("--out", default="access_check_results.json")
    ap.add_argument("--delay", type=float, default=0.3,
                     help="seconds to sleep between requests (be polite / respect rate limits)")
    ap.add_argument("--timeout", type=float, default=10.0)
    args = ap.parse_args()

    cfg = load_config(args.config)
    base_url = cfg["base_url"]
    sessions = cfg["sessions"]
    owned_ids = cfg.get("owned_ids", {})
    templates = cfg["templates"]
    id_range = [str(i) for i in cfg["id_range"]]

    results = []
    total = len(templates) * len(sessions) * len(id_range)
    done = 0

    print(f"[*] {total} requests planned ({len(templates)} templates x "
          f"{len(sessions)} sessions x {len(id_range)} ids)")
    print("[*] Only run this against targets you are authorized to test.\n")

    for template in templates:
        for session_name, session_cfg in sessions.items():
            for obj_id in id_range:
                r = probe(base_url, session_name, session_cfg, template,
                          obj_id, owned_ids, args.delay, args.timeout)
                results.append(r)
                done += 1
                marker = f" <-- {r.flag}" if r.flag else ""
                print(f"[{done}/{total}] {r.session:8s} {r.method:6s} "
                      f"{r.url:60s} {r.status:4d} {r.length:8d}{marker}")

    with open(args.out, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2)

    flagged = [r for r in results if r.flag]
    print(f"\n[*] Done. {len(flagged)} flagged result(s) out of {len(results)}.")
    print(f"[*] Full results written to {args.out}")
    if flagged:
        print("\n[!] REVIEW THESE MANUALLY -- flags are heuristics, not confirmed bugs:")
        for r in flagged:
            print(f"    - {r.flag}: session={r.session} id={r.id_tested} "
                  f"(owned by {r.owned_by}) -> {r.status} {r.url}")


if __name__ == "__main__":
    main()
