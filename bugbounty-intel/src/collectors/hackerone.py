"""HackerOne Hacktivity collector (§2, §37).

Requires the user's own HackerOne API credentials (a HackerOne account has
an API identifier + API token under Settings -> API Token). This tool never
ships or hardcodes credentials, and never fabricates report data (§38) - if
a field isn't present in the API response, it is stored as None/'not
disclosed', never guessed.

Set credentials via environment variables:
    HACKERONE_API_USERNAME
    HACKERONE_API_TOKEN

The exact endpoint path/parameter names here follow the structure described
in the project spec (GET /hackers/hacktivity, Lucene-style filters). HackerOne's
API does evolve - treat https://api.hackerone.com/hacker-resources/ as
authoritative and update BASE_URL/params here if they've changed since this
was written.
"""
import os
import time

import requests

BASE_URL = "https://api.hackerone.com/v1/hackers/hacktivity"
UA = {"User-Agent": "bugbounty-intel/0.1 (authorized-security-research)"}

RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class HackerOneAuthError(RuntimeError):
    pass


def _credentials():
    user = os.environ.get("HACKERONE_API_USERNAME")
    token = os.environ.get("HACKERONE_API_TOKEN")
    if not user or not token:
        raise HackerOneAuthError(
            "Set HACKERONE_API_USERNAME and HACKERONE_API_TOKEN environment "
            "variables (from your HackerOne account's API Token settings) "
            "before running 'bugbounty-intel sync --source hackerone'."
        )
    return user, token


def fetch_page(query=None, page=1, page_size=25, timeout=20, max_retries=5):
    """Fetches one page of public Hacktivity results. query is a Lucene-style
    filter string per the fields listed in §2 (severity_rating, cwe,
    disclosed, etc.) - passed through verbatim to the API's query parameter."""
    user, token = _credentials()
    params = {"page[number]": page, "page[size]": page_size}
    if query:
        params["queryString"] = query

    backoff = 2
    for attempt in range(max_retries):
        resp = requests.get(
            BASE_URL, params=params, headers=UA, auth=(user, token), timeout=timeout
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in RETRYABLE_STATUS and attempt < max_retries - 1:
            retry_after = resp.headers.get("Retry-After")
            wait = float(retry_after) if retry_after else backoff
            time.sleep(wait)
            backoff *= 2
            continue
        resp.raise_for_status()
    raise RuntimeError("HackerOne API: exhausted retries for page {}".format(page))


def normalize_report(raw):
    """Maps a raw Hacktivity API item to the schema in §2/§25. Only fields
    actually present in the API response are populated - everything else is
    left None rather than guessed (§38)."""
    attrs = raw.get("attributes", {}) if isinstance(raw, dict) else {}
    report_id = str(raw.get("id", "")) if isinstance(raw, dict) else ""
    return {
        "source": "hackerone",
        "report_id": report_id,
        "title": attrs.get("title"),
        "url": "https://hackerone.com/reports/{}".format(report_id) if report_id else None,
        "disclosed_at": attrs.get("disclosed_at") or attrs.get("latest_disclosable_activity_at"),
        "submitted_at": attrs.get("submitted_at") or attrs.get("submitted_at_hacktivity_item"),
        "severity": attrs.get("severity_rating"),
        "cwe": attrs.get("cwe") or attrs.get("weakness"),
        "cve_ids": attrs.get("cve_ids", []) or [],
        "bounty": attrs.get("total_awarded_amount"),
        "votes": attrs.get("total_votes", 0) or 0,
        "team": attrs.get("team_handle") or attrs.get("team_name"),
        "reporter": attrs.get("reporter_username"),
        "disclosed": bool(attrs.get("disclosed", False)),
        "summary": attrs.get("summary") or attrs.get("vulnerability_information"),
        "raw_source": str(raw),
        # Not populated by the raw API response - left for the classifier
        # step (§3) to fill in from the report body, never guessed here.
        "owasp": None,
        "family": None,
        "technique": None,
        "attack_surface": None,
        "authentication": None,
        "interaction": None,
        "payload_disclosure": "none",
    }


def iter_reports(query=None, page_size=25, max_pages=None):
    page = 1
    while True:
        data = fetch_page(query=query, page=page, page_size=page_size)
        items = data.get("data", [])
        if not items:
            return
        for item in items:
            yield normalize_report(item)
        page += 1
        if max_pages and page > max_pages:
            return
