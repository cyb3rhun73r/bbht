# Data model

See `src/database/schema.sql` for the authoritative definitions. Summary:

- **payloads** - one row per distinct (category, normalized_payload). Carries risk classification, purpose, OWASP/CWE tags, and automation-safety flags.
- **payload_variants** - one row per (payload, source) pair, so the same payload appearing in two sources keeps both provenance records (§30).
- **sources** - registry of data sources (portswigger, payloadsallthethings, hackerone, internal).
- **hacktivity_reports** - normalized HackerOne Hacktivity reports (§2/§25). Never fabricated - missing fields stay `NULL`.
- **hacktivity_payloads** - payloads/PoCs extracted from a report, tagged `payload_origin` = `directly_disclosed` or `derived` (§24).
- **owasp_categories** / **cwe** - taxonomy reference tables, loaded from `data/taxonomy/*.json`.
- **observations** - a record of any SAFE_ACTIVE test actually run against a target (for the safety engine's audit trail once wired in - see docs/architecture.md Phase 5).

Relationship (§31):

```
payload -> vulnerability family -> CWE -> OWASP -> related HackerOne reports -> source references
```
