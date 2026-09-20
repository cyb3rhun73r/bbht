"""Collector for the PayloadsAllTheThings GitHub repository (§6).

Fetches the repo's file tree via the GitHub API and lets the caller inspect
which vulnerability-category directories are present. Full markdown parsing
into structured payload records (per the schema in §7) is deliberately left
as a targeted, per-category job rather than a bulk importer - the spec is
explicit that we must NOT blindly import every file (§6: "Do NOT blindly
import every repository file"), and PayloadsAllTheThings' markdown files mix
prose, curl commands and payload snippets in inconsistent formats per
directory, so a naive blanket parser produces low-quality, wrongly-tagged
records. The curated seed set in data/payloads/*.json already captures the
canonical payloads from this repo with correct category/context/risk tags;
use this collector to check for new categories/files worth curating next.
"""
import requests

REPO_API = "https://api.github.com/repos/swisskyrepo/PayloadsAllTheThings"
UA = {"User-Agent": "bugbounty-intel/0.1 (authorized-security-research)"}


def list_top_level_categories(timeout=15):
    """Returns the repo's top-level directory names (each one is a
    vulnerability category, e.g. 'XSS Injection', 'SQL Injection')."""
    resp = requests.get(REPO_API + "/contents", headers=UA, timeout=timeout)
    resp.raise_for_status()
    return sorted(
        entry["name"] for entry in resp.json()
        if entry["type"] == "dir" and not entry["name"].startswith(".")
    )


def fetch_readme(category_dir, timeout=15):
    """Fetches the raw README.md for a given top-level category directory,
    for manual review before curating new payload entries from it."""
    url = "https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/{}/README.md".format(
        category_dir
    )
    resp = requests.get(url, headers=UA, timeout=timeout)
    resp.raise_for_status()
    return resp.text


def repo_head_commit(timeout=15):
    """Latest commit SHA on master - used by the sync engine (§36) to detect
    whether the repo has changed since the last curation pass."""
    resp = requests.get(REPO_API + "/commits/master", headers=UA, timeout=timeout)
    resp.raise_for_status()
    return resp.json()["sha"]
