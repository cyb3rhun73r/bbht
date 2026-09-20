-- bugbounty-intel schema
-- Authorized security-research payload/report intelligence database.

CREATE TABLE IF NOT EXISTS sources (
    id              TEXT PRIMARY KEY,       -- e.g. 'portswigger', 'payloadsallthethings', 'hackerone'
    name            TEXT NOT NULL,
    base_url        TEXT,
    license_note    TEXT,
    last_synced_at  TEXT
);

CREATE TABLE IF NOT EXISTS owasp_categories (
    code    TEXT PRIMARY KEY,   -- 'A01'
    name    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cwe (
    code    TEXT PRIMARY KEY,   -- 'CWE-79'
    name    TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS technologies (
    name    TEXT PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS contexts (
    name    TEXT PRIMARY KEY   -- 'html', 'attribute', 'javascript', ...
);

CREATE TABLE IF NOT EXISTS tags (
    name    TEXT PRIMARY KEY
);

-- Canonical payload record (one per distinct payload string + category).
CREATE TABLE IF NOT EXISTS payloads (
    id                          TEXT PRIMARY KEY,
    category                    TEXT NOT NULL,      -- 'xss', 'sqli', 'ssrf', ...
    subcategory                 TEXT,
    payload                     TEXT NOT NULL,
    normalized_payload          TEXT NOT NULL,
    context                     TEXT,
    purpose                     TEXT NOT NULL,       -- fingerprint/detection/context-breakout/...
    detection_method            TEXT,
    expected_indicator          TEXT,
    false_positive_notes        TEXT,
    risk_level                  TEXT NOT NULL,       -- SAFE/LOW/MEDIUM/HIGH/RESTRICTED
    safe_for_automation         INTEGER NOT NULL DEFAULT 0,
    requires_manual_validation  INTEGER NOT NULL DEFAULT 1,
    destructive                 INTEGER NOT NULL DEFAULT 0,
    credential_access           INTEGER NOT NULL DEFAULT 0,
    data_exfiltration           INTEGER NOT NULL DEFAULT 0,
    persistence                 INTEGER NOT NULL DEFAULT 0,
    owasp                       TEXT,                -- comma-separated codes
    cwe                         TEXT,                -- comma-separated codes
    first_seen                  TEXT,
    last_seen                   TEXT
);

-- A payload can come from more than one source (dedup keeps both refs).
CREATE TABLE IF NOT EXISTS payload_variants (
    id                  TEXT PRIMARY KEY,
    payload_id          TEXT NOT NULL REFERENCES payloads(id),
    source_id           TEXT NOT NULL REFERENCES sources(id),
    source_url          TEXT,
    source_file         TEXT,
    source_line         INTEGER,
    original_text       TEXT NOT NULL,
    encoding            TEXT,                       -- 'plain', 'url_encoded', ...
    source_disclosed    INTEGER NOT NULL DEFAULT 1,
    retrieved_at        TEXT,
    content_hash        TEXT
);

CREATE TABLE IF NOT EXISTS hacktivity_reports (
    report_id       TEXT PRIMARY KEY,
    source          TEXT NOT NULL DEFAULT 'hackerone',
    title           TEXT,
    url             TEXT,
    disclosed_at    TEXT,
    submitted_at    TEXT,
    severity        TEXT,
    cwe             TEXT,
    cve_ids         TEXT,           -- JSON array as text
    bounty          REAL,
    votes           INTEGER,
    team            TEXT,
    reporter        TEXT,
    disclosed       INTEGER,
    summary         TEXT,
    owasp           TEXT,
    family          TEXT,
    technique       TEXT,
    attack_surface  TEXT,
    authentication  TEXT,
    interaction     TEXT,
    payload_disclosure TEXT NOT NULL DEFAULT 'none',  -- none/directly_disclosed/derived
    raw_source      TEXT
);

CREATE TABLE IF NOT EXISTS hacktivity_payloads (
    id              TEXT PRIMARY KEY,
    report_id       TEXT NOT NULL REFERENCES hacktivity_reports(report_id),
    payload_origin  TEXT NOT NULL,   -- directly_disclosed / derived
    payload_text    TEXT,
    notes           TEXT
);

CREATE TABLE IF NOT EXISTS observations (
    id              TEXT PRIMARY KEY,
    target          TEXT NOT NULL,
    payload_id      TEXT REFERENCES payloads(id),
    mode            TEXT NOT NULL,     -- PASSIVE/SAFE_ACTIVE/MANUAL
    result          TEXT,
    evidence        TEXT,
    created_at      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_payloads_category ON payloads(category);
CREATE INDEX IF NOT EXISTS idx_payloads_risk ON payloads(risk_level);
CREATE INDEX IF NOT EXISTS idx_variants_payload ON payload_variants(payload_id);
CREATE INDEX IF NOT EXISTS idx_hacktivity_cwe ON hacktivity_reports(cwe);
CREATE INDEX IF NOT EXISTS idx_hacktivity_owasp ON hacktivity_reports(owasp);
