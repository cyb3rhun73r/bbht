# SSRF — Real Disclosed-Report Pattern Library

SSRF is one of the highest-value, most learnable bug classes — it doesn't
need deep exploit-dev skill, just knowing which fields fetch a URL
server-side and how to prove impact via cloud metadata or internal-network
access. Drawn from disclosed HackerOne reports.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Third-party connector/integration fields** | Bime (H1 #112156) | SSRF in a "Connector Designer" (REST integration builder) — any feature that lets a user configure a URL for the app to call is a prime SSRF candidate. |
| **CI/CD runner metadata access** | GitLab (H1 #369451) | GitLab CI runners didn't restrict access to Google Cloud instance metadata APIs — a malicious CI job could mint a service token and reach internal buckets with private keys/logs. Check any CI/build feature you can control. |
| **Legacy API version bypass** | Shopify (H1 #341876) | The old `/v1beta1` GCP metadata endpoint didn't require the `Metadata-Flavor: Google` header that newer endpoints enforce, and still returned the same token — if a metadata-header check exists, try the deprecated endpoint version that predates it. |
| **Webhook URL fields** | Mixmax (H1 #243277) | SSRF via the account webhook feature — webhooks are one of the single most common SSRF entry points across all programs. Enumerate the EC2 metadata URL, or probe for internal service existence. |
| **DNS rebinding to bypass allowlists** | Snapchat (H1 #530974) | A custom page using DNS rebinding (DNS resolves to attacker IP at validation time, then internal IP at request time) bypassed a URL-validation allowlist to reach Google's internal metadata service. Use this when a naive "resolve and check the IP" filter is in place. |
| **Direct AWS metadata read via a scan/fetch feature** | DoD (H1 #1623685, #1624140, #1628102) | Multiple DoD reports: SSRF in various "fetch this URL"-style features used to read AWS instance metadata (`169.254.169.254`), sometimes achieving full internal read access, not just metadata. |

## Fast test approach
1. **Find candidate fields**: any feature where the server fetches a URL you provide — webhooks, "import from URL," link previews/unfurling, PDF/screenshot generation, avatar-from-URL, RSS/feed importers, SSO/OAuth callback URLs, file-import-by-URL, CI/CD integration configs, third-party connector setup.
2. **Confirm out-of-band (safest first step)**: point the field at your own `interactsh-client` listener or Burp Collaborator URL. A DNS/HTTP callback confirms server-side fetch is happening, with zero risk of touching real internal infra.
3. **Escalate to impact once confirmed**:
   - Cloud metadata: `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS), `http://169.254.169.254/computeMetadata/v1/` with `Metadata-Flavor: Google` header (GCP — also try without the header on older API versions, per the Shopify example above).
   - Internal network: try common internal ranges (`127.0.0.1`, `10.x`, `192.168.x`, `169.254.x`) and common internal ports (redis 6379, internal admin panels).
4. **If a URL allowlist/validator blocks obvious targets**, try:
   - DNS rebinding (per Snapchat example)
   - Alternate IP encodings: decimal (`2130706433` = 127.0.0.1), octal, IPv6 (`::1`, `::ffff:127.0.0.1`), or a redirect chain (`http://attacker.com/redirect` → 302 → internal target, if the fetcher follows redirects)
   - URL parser confusion (`http://allowed-domain.com@169.254.169.254/`, `http://169.254.169.254#allowed-domain.com`)
5. **For blind SSRF (no response body returned)**: rely entirely on the OOB callback (step 2) for detection, and time-based signals (does the request hang longer when pointed at a closed internal port vs. an open one?) to infer internal network topology.

## Tools
- `interactsh-client` (ProjectDiscovery) for OOB confirmation — this is the single most useful tool for SSRF since most real-world instances are blind.
- Burp Collaborator as an alternative.
- Nuclei has SSRF-detection templates (`nuclei -tags ssrf`) that automate the OOB-probe step across many endpoints at once — good for initial sweep, but manual field-by-field testing finds the ones templates miss (custom integration/webhook features are rarely covered generically).
