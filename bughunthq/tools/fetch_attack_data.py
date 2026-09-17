#!/usr/bin/env python3
"""
Fetches the official MITRE ATT&CK (Enterprise) dataset and builds two small,
fast-to-load local files Bug Hunt HQ uses to keep its tactic/technique
mappings automated instead of hand-typed:

    tools/attack-data/enterprise-attack-index.json
        Every non-deprecated technique/sub-technique: id -> {name, tactics,
        url, sub}. Used to resolve and VALIDATE every MITRE code the
        suggestion engine emits against the live, official data - if a
        technique gets renamed or deprecated upstream, this catches it
        instead of silently showing a stale label.

    tools/attack-data/webapp-relevant.json
        A curated subset of technique IDs whose tactic sits in the web-app
        exploitation kill chain (recon through collection/exfiltration) and
        whose name/description mentions a web-relevant keyword. Powers the
        app's "MITRE Reference" tab - a browsable, always-current-if-you-
        rerun-this cheat sheet, independent of what your last recon found.

Source: https://github.com/mitre-attack/attack-stix-data (official MITRE
ATT&CK STIX 2.1 export, Enterprise domain). Nothing is written to disk in
raw form - the ~50MB bundle is parsed in memory and only the compact index
(a few hundred KB) is kept.

Run once, and re-run any time you want the mappings refreshed against the
current ATT&CK release:

    python tools\\fetch_attack_data.py

Authorized security testing only - see the app's Legal/About tab.
"""
import json
import os
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.join(HERE, "attack-data")
SOURCE_URL = ("https://raw.githubusercontent.com/mitre-attack/"
              "attack-stix-data/master/enterprise-attack/enterprise-attack.json")
UA = {"User-Agent": "BugHuntHQ-attack-data-fetcher"}

# Tactics that make up the web-application exploitation kill chain (i.e.
# excludes purely internal-network/lateral-movement-only tactics that rarely
# apply from the outside-in perspective of a bug hunter).
WEBAPP_TACTICS = {
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "credential-access", "discovery",
    "collection", "exfiltration", "impact",
}

WEBAPP_KEYWORDS = [
    "web", "application", "http", "api", "server", "browser", "cookie",
    "session", "credential", "cloud", "container", "script", "injection",
    "phishing", "link", "database", "sql", "certificate", "token", "oauth",
    "saml", "jwt", "repository", "storage", "bucket", "metadata", "proxy",
    "dns", "domain", "account", "password", "exploit public-facing",
]


def fetch_bundle():
    print("[*] Downloading MITRE ATT&CK Enterprise dataset (~50MB, in memory only)...")
    req = urllib.request.Request(SOURCE_URL, headers=UA)
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp)


def tactic_name(phase_name):
    return phase_name.replace("-", " ").title()


def build_index(bundle):
    index = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        ext_id, url = None, None
        for ref in obj.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                ext_id = ref.get("external_id")
                url = ref.get("url")
                break
        if not ext_id:
            continue
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack"]
        index[ext_id] = {
            "name": obj.get("name", ""),
            "tactics": tactics,
            "tactics_display": [tactic_name(t) for t in tactics],
            "url": url or "",
            "sub": bool(obj.get("x_mitre_is_subtechnique", False)),
            "description": (obj.get("description") or "").split("\n")[0][:300],
        }
    return index


def build_webapp_subset(index):
    ids = []
    for ext_id, rec in index.items():
        if not any(t in WEBAPP_TACTICS for t in rec["tactics"]):
            continue
        blob = (rec["name"] + " " + rec["description"]).lower()
        if any(kw in blob for kw in WEBAPP_KEYWORDS):
            ids.append(ext_id)
    ids.sort(key=lambda i: (index[i]["tactics"][0] if index[i]["tactics"] else "zzz", i))
    return ids


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    try:
        bundle = fetch_bundle()
    except Exception as e:
        print("[!] Could not download the ATT&CK dataset: {}".format(e))
        print("    Bug Hunt HQ will keep using its built-in fallback technique labels.")
        return

    index = build_index(bundle)
    print("[+] Indexed {} non-deprecated techniques/sub-techniques".format(len(index)))

    webapp_ids = build_webapp_subset(index)
    print("[+] {} of those are tagged web-app-relevant".format(len(webapp_ids)))

    version = "unknown"
    for obj in bundle.get("objects", []):
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", version)
            break

    index_path = os.path.join(OUT_DIR, "enterprise-attack-index.json")
    with open(index_path, "w", encoding="utf-8") as fh:
        json.dump({"attack_version": version, "techniques": index}, fh)
    print("[+] Wrote {}".format(index_path))

    webapp_path = os.path.join(OUT_DIR, "webapp-relevant.json")
    with open(webapp_path, "w", encoding="utf-8") as fh:
        json.dump({"attack_version": version, "technique_ids": webapp_ids}, fh)
    print("[+] Wrote {}".format(webapp_path))

    print("\nDone. Bug Hunt HQ will pick these up automatically on next launch -")
    print("check the Recon Log tab at startup and the new 'MITRE Reference' tab.")


if __name__ == "__main__":
    main()
