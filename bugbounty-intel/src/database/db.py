"""SQLite access layer for bugbounty-intel.

Authorized security-research tool. See docs/safety.md.
"""
import hashlib
import json
import os
import sqlite3
from pathlib import Path

SCHEMA_PATH = Path(__file__).parent / "schema.sql"
DEFAULT_DB_PATH = Path(os.environ.get("BBINTEL_DB", str(Path.home() / ".bugbounty-intel" / "data.sqlite3")))


def connect(db_path=None):
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db(conn):
    with open(SCHEMA_PATH, "r", encoding="utf-8") as fh:
        conn.executescript(fh.read())
    conn.commit()


def normalize_payload(text):
    """Collapse whitespace/case-insensitive encoding noise for dedup matching,
    while the original text is always preserved separately (see §30/§10)."""
    return " ".join(text.strip().split()).lower()


def content_hash(text):
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def upsert_source(conn, source_id, name, base_url="", license_note=""):
    conn.execute(
        "INSERT INTO sources (id, name, base_url, license_note) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(id) DO UPDATE SET name=excluded.name, base_url=excluded.base_url, "
        "license_note=excluded.license_note",
        (source_id, name, base_url, license_note),
    )


def touch_source_synced(conn, source_id, when_iso):
    conn.execute("UPDATE sources SET last_synced_at=? WHERE id=?", (when_iso, source_id))


def find_payload_id(conn, category, normalized):
    row = conn.execute(
        "SELECT id FROM payloads WHERE category=? AND normalized_payload=?",
        (category, normalized),
    ).fetchone()
    return row["id"] if row else None


def upsert_payload(conn, record):
    """record: dict matching the payload schema in §7. Dedupes on
    (category, normalized_payload) - see §30. Returns the payload id."""
    normalized = normalize_payload(record["payload"])
    existing_id = find_payload_id(conn, record["category"], normalized)
    payload_id = existing_id or record["id"]

    if existing_id:
        conn.execute(
            "UPDATE payloads SET last_seen=? WHERE id=?",
            (record.get("last_seen"), existing_id),
        )
    else:
        conn.execute(
            """INSERT INTO payloads (
                id, category, subcategory, payload, normalized_payload, context,
                purpose, detection_method, expected_indicator, false_positive_notes,
                risk_level, safe_for_automation, requires_manual_validation,
                destructive, credential_access, data_exfiltration, persistence,
                owasp, cwe, first_seen, last_seen
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                payload_id, record["category"], record.get("subcategory"),
                record["payload"], normalized, record.get("context"),
                record["purpose"], record.get("detection_method"),
                record.get("expected_indicator"), record.get("false_positive_notes"),
                record["risk_level"], int(record.get("safe_for_automation", False)),
                int(record.get("requires_manual_validation", True)),
                int(record.get("destructive", False)), int(record.get("credential_access", False)),
                int(record.get("data_exfiltration", False)), int(record.get("persistence", False)),
                ",".join(record.get("owasp", [])), ",".join(record.get("cwe", [])),
                record.get("first_seen"), record.get("last_seen"),
            ),
        )

    variant = record.get("_variant", {})
    variant_id = "{}-{}".format(payload_id, content_hash(variant.get("source_id", "") + normalized)[:12])
    conn.execute(
        """INSERT OR IGNORE INTO payload_variants (
            id, payload_id, source_id, source_url, source_file, source_line,
            original_text, encoding, source_disclosed, retrieved_at, content_hash
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
            variant_id, payload_id, variant.get("source_id"), variant.get("source_url"),
            variant.get("source_file"), variant.get("source_line"), record["payload"],
            variant.get("encoding", "plain"), int(variant.get("source_disclosed", True)),
            variant.get("retrieved_at"), content_hash(record["payload"]),
        ),
    )
    return payload_id


def upsert_hacktivity_report(conn, report):
    """report: dict matching the HackerOne normalized schema in §2/§25. Never
    fabricate missing fields - pass None/'' through as-is (see §38)."""
    conn.execute(
        """INSERT INTO hacktivity_reports (
            report_id, source, title, url, disclosed_at, submitted_at, severity,
            cwe, cve_ids, bounty, votes, team, reporter, disclosed, summary,
            owasp, family, technique, attack_surface, authentication, interaction,
            payload_disclosure, raw_source
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        ON CONFLICT(report_id) DO UPDATE SET
            title=excluded.title, url=excluded.url, disclosed_at=excluded.disclosed_at,
            severity=excluded.severity, cwe=excluded.cwe, cve_ids=excluded.cve_ids,
            bounty=excluded.bounty, votes=excluded.votes, disclosed=excluded.disclosed,
            summary=excluded.summary, owasp=excluded.owasp, family=excluded.family,
            technique=excluded.technique, attack_surface=excluded.attack_surface,
            authentication=excluded.authentication, interaction=excluded.interaction,
            payload_disclosure=excluded.payload_disclosure, raw_source=excluded.raw_source""",
        (
            report["report_id"], report.get("source", "hackerone"), report.get("title"),
            report.get("url"), report.get("disclosed_at"), report.get("submitted_at"),
            report.get("severity"), report.get("cwe"), json.dumps(report.get("cve_ids", [])),
            report.get("bounty"), report.get("votes", 0), report.get("team"),
            report.get("reporter"), int(bool(report.get("disclosed", False))),
            report.get("summary"), report.get("owasp"), report.get("family"),
            report.get("technique"), report.get("attack_surface"),
            report.get("authentication"), report.get("interaction"),
            report.get("payload_disclosure", "none"), report.get("raw_source"),
        ),
    )
