# IDOR / Broken Object-Level Authorization (BOLA) — Real-World Pattern Taxonomy

Synthesized from a 2026 empirical study of 84+ confirmed bug bounty
disclosures ("Broken Object Level Authorization in the Wild: An Empirical
Taxonomy from 100+ Bug Bounty Disclosures", arXiv 2605.25865) plus disclosed
HackerOne reports and published writeups. Use this to prioritize *which*
endpoints to test first, not as an exhaustive list.

## The six BOLA families, by frequency

| Family | Share | What it is |
|---|---|---|
| **Action-Level Object BOLA** | 41.7% | Unauthorized *state-changing* operation (delete/modify/trigger) on another user's object. Most common, most under-tested by hunters who only check read access. |
| **Direct Object Reference BOLA** | 36.9% | Classic IDOR — swap an ID in the request, read someone else's data. |
| **Tenant Isolation BOLA** | 8.3% | Cross-organization access in multi-tenant SaaS — missing membership/tenant check lets account in Org A reach Org B's data. |
| **Workflow-Context BOLA** | 6.0% | Authorization that was valid in one object lifecycle state (e.g. "active") isn't re-checked after a state change (e.g. "archived", "deactivated", "revoked"). |
| **Chained Disclosure BOLA** | 4.8% | Harvest an ID/token from endpoint A (which leaks it) to exploit authorization gap at endpoint B. |
| **Object Rebinding BOLA** | 2.4% | Client-supplied ownership field (`owner_id`, `account_id`, `user_id`) in a request body gets trusted, letting you reassign an object to yourself. |

**Takeaway:** don't stop at "can I read another user's object" — action-level
BOLA (can I *delete/modify/trigger* it) is actually the single largest
category and the one most hunters under-test.

## Identifier format breakdown
- Sequential integers: 36.9% of cases — easiest to find, still common.
- Non-sequential (UUIDs, encoded, hashed IDs): 39.2% — **don't skip these**
  assuming they're "random enough." Many are base64/hex-encoded sequential
  IDs, or leak elsewhere (emails, exports, other endpoints).
- **GraphQL Global IDs** are systematically exploited via a
  decode → increment/swap → re-encode pattern. If a target uses GraphQL,
  always check whether the opaque `id` field is just base64 of
  `Type:12345`.

## Authorization direction
- Horizontal (user-to-user): 85.7% of cases — most common, often
  lower-severity per-bug but easiest to find in volume.
- Vertical (user-to-admin): 11.9% — rarer but disproportionately high
  severity/payout.

## Action type
- Read: 52.4%
- Modify/Delete/Trigger (state-changing): 46.4% — test these even when
  read access is properly locked down; write paths are checked less often.

## Real disclosed examples (for calibration — what "found" looks like)

- **Palo Alto Software (H1 #854290)** — IDOR let a `USER`-role team member
  change another user's account data / steal session cookies via an
  endpoint that trusted a client-supplied user ID without checking
  team membership scope.
- **MTN Group (H1 #1272478)** — IDOR on a business portal led to full
  account takeover; found via Burp by systematically swapping a
  numeric identifier across authenticated requests.
- **U.S. DoD (H1 #741683)** — IDOR on a profile-upload endpoint: the
  upload target ID wasn't bound to the authenticated session.
- **HackerOne's own GraphQL endpoint (H1 #489146)** — leaked confidential
  data about *private* bug bounty programs to any authenticated user,
  because a resolver had no ownership/authorization check at all — a
  classic "someone forgot the check on this one field" bug.
- **Shopify (H1 #2207248, $5,000)** — IDOR on `BillingDocumentDownload`
  and `BillDetails` GraphQL queries — billing/financial documents are a
  recurring high-value target for IDOR because they're often bolted onto
  an app later, with weaker authz than the core resource.
- **$12,500 GraphQL finding** — publicly enabled introspection let a
  researcher map the full schema, then chain batch-query processing with
  IDOR to pull other users' financial transactions (CVSS 9.1). Lesson:
  always check `__schema` introspection on GraphQL targets first — it's
  free reconnaissance most programs forget to disable.

## Where to look first (highest hit-rate locations)
1. **Export / download / PDF-generation / "email me a copy" endpoints** —
   consistently under-protected relative to the normal view page for the
   same resource.
2. **Billing, invoices, financial documents** — bolted on later, often
   with separate (weaker) authz logic than the core app.
3. **GraphQL mutations**, not just queries — action-level BOLA lives here.
4. **Bulk/batch endpoints** (`/api/items?ids=1,2,3`) — sometimes check
   authz on the first ID only, not each one in the batch.
5. **Any endpoint that changed state on an object** (archive, revoke,
   deactivate, cancel) — re-test authz after the state change, not just
   before it (Workflow-Context BOLA).
6. **Support/ticketing systems** — ticket ID in URL/API param is one of
   the single most repeated IDOR patterns in disclosed reports.

## How to test systematically
Use `scripts/access_check.py` in this repo to automate the replay-and-diff
part: register 2+ test accounts, create one resource per account, then
sweep every endpoint above across both accounts' IDs and an unauthenticated
session. It flags likely cross-account access for you to manually confirm.
