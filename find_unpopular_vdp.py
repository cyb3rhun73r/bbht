#!/usr/bin/env python3
"""find_unpopular_vdp.py - discover lesser-known vulnerability disclosure programs.

Most bug bounty hunters pile onto the same high-profile, high-reward programs
hosted on the big platforms (HackerOne, Bugcrowd, Intigriti, ...). Those get
saturated fast. This helper surfaces the *unpopular* / low-competition end of
the spectrum instead: self-managed vulnerability disclosure programs (VDPs) that
often have no monetary bounty, publish a direct contact channel, and rarely make
it onto a platform leaderboard.

Every program listed here has voluntarily published a disclosure policy inviting
researchers to report issues responsibly. Data comes from the community-run,
public disclose.io directory (https://github.com/disclose/diodb). Use the output
only for authorized, good-faith security research and coordinated disclosure, and
always follow each program's own policy and scope.

No third-party dependencies - standard library only.
"""

import argparse
import json
import sys
import urllib.request
from urllib.error import URLError, HTTPError

# Community-maintained, public program directory (disclose.io "diodb").
DEFAULT_SOURCE = (
    "https://raw.githubusercontent.com/disclose/diodb/master/program-list.json"
)

# Substrings that mark a program as managed on a large, crowded platform.
# Presence of any of these => lots of researcher competition => "popular".
CROWDED_PLATFORMS = (
    "hackerone.com",
    "bugcrowd.com",
    "intigriti.com",
    "yeswehack.com",
    "hackenproof.com",
    "immunefi.com",
    "openbugbounty.org",
    "synack.com",
    "cobalt.io",
    "zerocopter.com",
    "hackerplatform.com",
)


def fetch_programs(source):
    """Load the program list from a URL or a local file path."""
    if source.startswith(("http://", "https://")):
        try:
            req = urllib.request.Request(
                source, headers={"User-Agent": "bbht-find-unpopular-vdp"}
            )
            with urllib.request.urlopen(req, timeout=45) as resp:
                raw = resp.read().decode("utf-8", errors="replace")
        except (URLError, HTTPError) as exc:
            sys.exit(f"error: could not fetch program list from {source}: {exc}")
    else:
        try:
            with open(source, "r", encoding="utf-8") as fh:
                raw = fh.read()
        except OSError as exc:
            sys.exit(f"error: could not read program list from {source}: {exc}")

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        sys.exit(f"error: program list is not valid JSON: {exc}")

    if not isinstance(data, list):
        sys.exit("error: unexpected program list format (expected a JSON array)")
    return data


def _is_platform_managed(program):
    """True if the program's URLs point at a crowded bug bounty platform."""
    haystack = " ".join(
        str(program.get(field, "")).lower()
        for field in ("policy_url", "contact_url", "securitytxt_url")
    )
    return any(platform in haystack for platform in CROWDED_PLATFORMS)


def _has_direct_contact(program):
    return bool(program.get("contact_email") or program.get("securitytxt_url"))


def check_policy_link(url, timeout=15):
    """Ping a policy URL and report its state.

    Returns a dict: {"status": <http code or 'error'>, "final_url": <str>,
    "redirected": <bool>, "note": <short label>}. Used to catch rebrands
    (amoCRM -> Kommo) and dead policy pages before you rely on a listing.
    urllib follows redirects, so comparing the final URL to the original
    reveals a move; bot-blockers (Cloudflare) show up as 403/503.
    """
    if not url or not str(url).startswith(("http://", "https://")):
        return {"status": "n/a", "final_url": url, "redirected": False,
                "note": "no url"}
    headers = {"User-Agent": "Mozilla/5.0 (bbht-find-unpopular-vdp)"}
    for method in ("HEAD", "GET"):
        try:
            req = urllib.request.Request(url, headers=headers, method=method)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                final = resp.geturl()
                redirected = final.rstrip("/") != url.rstrip("/")
                return {
                    "status": resp.status,
                    "final_url": final,
                    "redirected": redirected,
                    "note": f"moved -> {final}" if redirected else "ok",
                }
        except HTTPError as exc:
            # 405 => server dislikes HEAD; retry with GET before giving up.
            if method == "HEAD" and exc.code in (403, 405, 501):
                continue
            note = "blocked (bot filter)" if exc.code in (403, 503) else "dead"
            return {"status": exc.code, "final_url": url, "redirected": False,
                    "note": note}
        except (URLError, OSError) as exc:
            return {"status": "error", "final_url": url, "redirected": False,
                    "note": f"unreachable ({exc.reason if hasattr(exc, 'reason') else exc})"}
    return {"status": "error", "final_url": url, "redirected": False,
            "note": "unreachable"}


def obscurity_score(program):
    """Higher score => less popular / lower competition but still reachable.

    The heuristic rewards the traits that keep the crowds away (no cash bounty,
    not on a big platform) while still favouring programs a researcher can
    actually engage with responsibly (a direct contact channel, safe harbour).
    """
    score = 0
    bounty = str(program.get("offers_bounty", "")).strip().lower()

    if bounty == "yes":
        score -= 5          # cash reward -> crowded
    elif bounty == "no":
        score += 3          # explicitly no bounty -> few hunters bother
    else:
        score += 1          # unknown -> mildly obscure

    if _is_platform_managed(program):
        score -= 5          # hosted where everyone already looks
    else:
        score += 2          # self-managed -> off the beaten path

    if not program.get("offers_swag"):
        score += 1          # no swag incentive -> less attention

    safe_harbor = str(program.get("safe_harbor", "")).strip().lower()
    if safe_harbor in ("full", "partial"):
        score += 1          # safer to engage responsibly

    if _has_direct_contact(program):
        score += 1          # a direct reporting channel exists

    return score


def _passes_filters(program, args):
    if args.no_bounty and str(program.get("offers_bounty", "")).lower() == "yes":
        return False
    if args.self_managed and _is_platform_managed(program):
        return False
    if args.safe_harbor and str(program.get("safe_harbor", "")).lower() not in (
        "full",
        "partial",
    ):
        return False
    if args.with_contact and not _has_direct_contact(program):
        return False
    return True


def _contact_of(program):
    return (
        program.get("contact_email")
        or program.get("contact_url")
        or program.get("securitytxt_url")
        or program.get("policy_url")
        or "-"
    )


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=(
            "Rank lesser-known / low-competition vulnerability disclosure "
            "programs from the public disclose.io directory."
        ),
        epilog="For authorized, good-faith security research only. "
        "Always follow each program's published policy and scope.",
    )
    parser.add_argument(
        "-s",
        "--source",
        default=DEFAULT_SOURCE,
        help="program list URL or local JSON file (default: disclose.io diodb)",
    )
    parser.add_argument(
        "-n",
        "--limit",
        type=int,
        default=25,
        help="number of programs to show (default: 25; use 0 for all)",
    )
    parser.add_argument(
        "--no-bounty",
        action="store_true",
        help="only programs that do NOT advertise a cash bounty",
    )
    parser.add_argument(
        "--self-managed",
        action="store_true",
        help="exclude programs hosted on big bug bounty platforms",
    )
    parser.add_argument(
        "--safe-harbor",
        action="store_true",
        help="only programs offering full or partial safe harbour",
    )
    parser.add_argument(
        "--with-contact",
        action="store_true",
        help="only programs that publish a direct contact channel",
    )
    parser.add_argument(
        "--check-links",
        action="store_true",
        help="ping the shown programs' policy URLs to flag redirects "
        "(rebrands) and dead links",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit results as JSON instead of a table",
    )
    args = parser.parse_args(argv)

    programs = fetch_programs(args.source)

    ranked = [
        {
            "program": p.get("program_name", "-"),
            "score": obscurity_score(p),
            "bounty": str(p.get("offers_bounty", "") or "unknown"),
            "platform_managed": _is_platform_managed(p),
            "safe_harbor": str(p.get("safe_harbor", "") or "-"),
            "contact": _contact_of(p),
            "policy_url": p.get("policy_url", "-"),
        }
        for p in programs
        if _passes_filters(p, args)
    ]
    # Highest obscurity first; stable tie-break by program name.
    ranked.sort(key=lambda r: (-r["score"], r["program"].lower()))

    if args.limit and args.limit > 0:
        ranked = ranked[: args.limit]

    # Only check the programs we actually show, so this stays fast and polite.
    if args.check_links:
        for r in ranked:
            r["link_check"] = check_policy_link(r["policy_url"])

    if args.json:
        print(json.dumps(ranked, indent=2))
        return

    total = len(programs)
    print(
        f"# {len(ranked)} lower-competition disclosure program(s) "
        f"(from {total} listed). Higher score = less popular / less crowded.\n"
    )
    if not ranked:
        print("No programs matched the given filters.")
        return

    header = f"{'SCORE':>5}  {'PROGRAM':<34}  {'BOUNTY':<8}  {'MANAGED':<9}  CONTACT"
    print(header)
    print("-" * len(header))
    for r in ranked:
        managed = "platform" if r["platform_managed"] else "self"
        program = (r["program"][:33] + "…") if len(r["program"]) > 34 else r["program"]
        contact = (r["contact"][:48] + "…") if len(r["contact"]) > 49 else r["contact"]
        print(
            f"{r['score']:>5}  {program:<34}  {r['bounty']:<8}  "
            f"{managed:<9}  {contact}"
        )

    if args.check_links:
        print("\n# Policy link check (redirects usually mean a rebrand):")
        for r in ranked:
            chk = r["link_check"]
            print(f"  [{str(chk['status']):>5}] {r['program']}: {chk['note']}")

    print(
        "\nReminder: engage only in authorized, good-faith research and follow "
        "each program's policy and scope."
    )


if __name__ == "__main__":
    main()
