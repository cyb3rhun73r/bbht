#!/usr/bin/env python3
"""gmail_osint - passive OSINT on a Gmail address using public sources only.

Modules:
  normalize  canonical form, dot/plus-tag variants, googlemail.com alias
  mx         verify the domain's mail records (DNS-over-HTTPS)
  gravatar   public Gravatar profile (name, linked accounts, avatar)
  github     public GitHub commits authored with the email + user matching
             the local part
  hibp       breach exposure (requires HIBP_API_KEY env var)

Only use on addresses you own or are authorized to investigate.
Standard library only. Python 3.8+.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "gmail-osint/1.0 (passive-recon)"
GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,}$")


def http_get(url, headers=None, timeout=10):
    """Return (status, parsed_json_or_text). Never raises on HTTP errors."""
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body, status = r.read().decode("utf-8", "replace"), r.status
    except urllib.error.HTTPError as e:
        body, status = e.read().decode("utf-8", "replace"), e.code
    except (urllib.error.URLError, TimeoutError) as e:
        return None, str(e)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, body


def normalize(email):
    local, domain = email.lower().rsplit("@", 1)
    info = {"input": email, "is_gmail": domain in GMAIL_DOMAINS}
    if not info["is_gmail"]:
        info["canonical"] = f"{local}@{domain}"
        return info
    base = local.split("+", 1)[0].replace(".", "")
    info.update(
        canonical=f"{base}@gmail.com",
        plus_tag=local.split("+", 1)[1] if "+" in local else None,
        username=base,
        alias=f"{base}@googlemail.com",
        note="Gmail ignores dots and +tags: all variants reach the same inbox.",
    )
    return info


def mx(domain):
    status, data = http_get(
        "https://dns.google/resolve?" + urllib.parse.urlencode({"name": domain, "type": "MX"})
    )
    if not isinstance(data, dict):
        return {"error": f"lookup failed: {data}"}
    records = [a["data"] for a in data.get("Answer", []) if a.get("type") == 15]
    return {"has_mx": bool(records), "records": records}


def gravatar(email):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    status, data = http_get(f"https://www.gravatar.com/{h}.json")
    if status == 404:
        return {"found": False}
    if not isinstance(data, dict):
        return {"error": f"status={status}"}
    e = (data.get("entry") or [{}])[0]
    return {
        "found": True,
        "profile_url": e.get("profileUrl"),
        "display_name": e.get("displayName"),
        "name": e.get("name"),
        "location": e.get("currentLocation"),
        "about": e.get("aboutMe"),
        "accounts": [
            {"service": a.get("shortname"), "url": a.get("url")}
            for a in e.get("accounts", [])
        ],
        "urls": [u.get("value") for u in e.get("urls", [])],
        "avatar": f"https://www.gravatar.com/avatar/{h}",
    }


def github(email, username):
    out = {}
    q = urllib.parse.quote(f"author-email:{email}")
    status, data = http_get(
        f"https://api.github.com/search/commits?q={q}&per_page=5",
        headers={"Accept": "application/vnd.github+json"},
    )
    if isinstance(data, dict) and "items" in data:
        users = {}
        for it in data["items"]:
            a = it.get("author") or {}
            if a.get("login"):
                users[a["login"]] = a.get("html_url")
        out["commit_matches"] = data.get("total_count", 0)
        out["users_from_commits"] = users
        out["repos"] = sorted({it["repository"]["full_name"] for it in data["items"]})
    else:
        out["commit_search"] = f"unavailable (status={status}; rate limit?)"

    status, data = http_get(f"https://api.github.com/users/{urllib.parse.quote(username)}")
    if status == 200 and isinstance(data, dict):
        out["username_match"] = {
            "login": data.get("login"),
            "name": data.get("name"),
            "url": data.get("html_url"),
            "created": data.get("created_at"),
            "note": "Same handle only - NOT confirmed to be the same person.",
        }
    else:
        out["username_match"] = None
    return out


def hibp(email):
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        return {"skipped": "set HIBP_API_KEY to enable (haveibeenpwned.com/API/Key)"}
    status, data = http_get(
        "https://haveibeenpwned.com/api/v3/breachedaccount/"
        + urllib.parse.quote(email)
        + "?truncateResponse=false",
        headers={"hibp-api-key": key},
    )
    if status == 404:
        return {"breached": False}
    if status == 200 and isinstance(data, list):
        return {
            "breached": True,
            "count": len(data),
            "breaches": [
                {"name": b["Name"], "date": b["BreachDate"], "data": b["DataClasses"]}
                for b in data
            ],
        }
    return {"error": f"status={status}"}


MODULES = ["normalize", "mx", "gravatar", "github", "hibp"]


def run(email, modules):
    email = email.strip()
    if not EMAIL_RE.match(email):
        raise ValueError(f"invalid email: {email}")
    norm = normalize(email)
    domain = email.rsplit("@", 1)[1].lower()
    res = {"target": email}
    if "normalize" in modules:
        res["normalize"] = norm
    if "mx" in modules:
        res["mx"] = mx(domain)
    # Gravatar/GitHub key on the exact and canonical address
    probe = norm["canonical"]
    if "gravatar" in modules:
        res["gravatar"] = gravatar(email)
        if not res["gravatar"].get("found") and probe != email.lower():
            alt = gravatar(probe)
            if alt.get("found"):
                res["gravatar"] = alt
    if "github" in modules:
        res["github"] = github(probe, norm.get("username") or email.split("@")[0])
    if "hibp" in modules:
        res["hibp"] = hibp(email)
    return res


def render(res):
    lines = [f"== {res['target']} =="]

    def section(title, d):
        lines.append(f"\n[{title}]")
        lines.append(json.dumps(d, indent=2, ensure_ascii=False))

    for m in MODULES:
        if m in res:
            section(m, res[m])
    return "\n".join(lines)


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("email", nargs="*", help="address(es) to investigate")
    p.add_argument("-f", "--file", help="file with one address per line")
    p.add_argument("-m", "--modules", default=",".join(MODULES),
                   help=f"comma list from: {','.join(MODULES)} (default: all)")
    p.add_argument("-j", "--json", action="store_true", help="JSON output")
    p.add_argument("-o", "--output", help="write output to file")
    a = p.parse_args()

    targets = list(a.email)
    if a.file:
        with open(a.file) as fh:
            targets += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    if not targets:
        p.error("provide at least one email")
    modules = [m.strip() for m in a.modules.split(",")]
    bad = set(modules) - set(MODULES)
    if bad:
        p.error(f"unknown module(s): {', '.join(sorted(bad))}")

    results = []
    for t in targets:
        try:
            results.append(run(t, modules))
        except ValueError as e:
            results.append({"target": t, "error": str(e)})

    if a.json:
        out = json.dumps(results if len(results) > 1 else results[0], indent=2, ensure_ascii=False)
    else:
        out = "\n\n".join(render(r) if "error" not in r else f"{r['target']}: {r['error']}" for r in results)
    if a.output:
        with open(a.output, "w") as fh:
            fh.write(out + "\n")
    else:
        print(out)


if __name__ == "__main__":
    sys.exit(main())
