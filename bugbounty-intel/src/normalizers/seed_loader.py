"""Loads the curated data/payloads/*.json seed files into SQLite.

These are hand-curated (not live-scraped - see docs/sources.md for why the
PortSwigger collector doesn't scrape live pages) but every entry carries real
provenance: a source id and a source_url pointing at the actual public page
or repository path the payload is documented on.
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ..database import db

DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "payloads"

SOURCE_META = {
    "portswigger": ("PortSwigger Web Security Academy", "https://portswigger.net/web-security"),
    "payloadsallthethings": ("PayloadsAllTheThings", "https://github.com/swisskyrepo/PayloadsAllTheThings"),
    "internal": ("bugbounty-intel (hand-authored, no external source)", ""),
}


def _now():
    return datetime.now(timezone.utc).isoformat()


def load_seed_file(conn, path):
    with open(path, "r", encoding="utf-8") as fh:
        records = json.load(fh)

    now = _now()
    count = 0
    for rec in records:
        source_id = rec.get("source_id", "internal")
        name, base_url = SOURCE_META.get(source_id, (source_id, ""))
        db.upsert_source(conn, source_id, name, base_url)

        payload_record = {
            "id": "{}-{}".format(rec["category"], uuid.uuid4().hex[:10]),
            "category": rec["category"],
            "subcategory": rec.get("subcategory"),
            "payload": rec["payload"],
            "context": rec.get("context"),
            "purpose": rec["purpose"],
            "detection_method": rec.get("detection_method"),
            "expected_indicator": rec.get("expected_indicator"),
            "false_positive_notes": rec.get("false_positive_notes"),
            "risk_level": rec["risk_level"],
            "safe_for_automation": rec.get("safe_for_automation", False),
            "requires_manual_validation": rec.get("requires_manual_validation", True),
            "destructive": rec.get("destructive", False),
            "credential_access": rec.get("credential_access", False),
            "data_exfiltration": rec.get("data_exfiltration", False),
            "persistence": rec.get("persistence", False),
            "owasp": rec.get("owasp", []),
            "cwe": rec.get("cwe", []),
            "first_seen": now,
            "last_seen": now,
            "_variant": {
                "source_id": source_id,
                "source_url": rec.get("source_url", ""),
                "source_file": str(path.name),
                "encoding": "plain",
                "source_disclosed": True,
                "retrieved_at": now,
            },
        }
        db.upsert_payload(conn, payload_record)
        count += 1
    return count


def load_all_seeds(conn, data_dir=None):
    data_dir = Path(data_dir) if data_dir else DATA_DIR
    total = 0
    files_loaded = []
    for path in sorted(data_dir.glob("*.json")):
        n = load_seed_file(conn, path)
        total += n
        files_loaded.append((path.name, n))
    conn.commit()
    return total, files_loaded
