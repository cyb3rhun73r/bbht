# Auth / JWT / Session Bypass — Real-World Pattern Library

Patterns drawn from disclosed HackerOne reports and published bug bounty
writeups. Use `scripts/jwt_probe.py` to generate the tampered variants
described below; always confirm manually against the real target response
before treating anything as a finding.

## JWT-specific bypasses

| Pattern | Disclosed example | What happened |
|---|---|---|
| **alg confusion (RS256→HS256)** | 8x8/Jitsi Meet (H1 #1210502, affecting versions < 2.0.5963) | A Prosody (XMPP server) JWT-auth module accepted symmetric algorithms even when the deployment was configured for asymmetric (RS256) signing. **Exact technique:** decode a legitimate token's header/payload, change `"alg": "RS256"` to `"alg": "HS256"`, then compute the new signature as `HMAC-SHA256(header.payload, <server's RSA public key as raw string>)` — the server's own verification code, when it sees `alg: HS256`, treats whatever key it has configured (the public key, meant only for verifying RS256 signatures) as the HMAC *secret* instead, so anyone who can fetch/know that public key (often exposed at a JWKS endpoint or in client config) can forge arbitrary valid tokens. This let an attacker mint tokens to join/control protected conference rooms with no real credentials. **In `jwt_probe.py` terms:** this is exactly what `--pubkey <server_public.pem>` does — fetch the target's public key (check `/.well-known/jwks.json`, app config, or client-side JS) and feed it in. |
| **Missing signature validation entirely** | Automattic Newspack plugin (H1 #2472798) | Registration/login endpoints never validated the JWT signature at all — arbitrary account registration and full auth bypass for any known email. |
| **Expired-claim not enforced** | Linktree (H1 #1760403) | Backend accepted tokens with an `exp` claim set in the past — no expiry enforcement server-side, enabling account takeover with a stale token. |
| **Empty signature accepted** | Partner portal writeup | Endpoint accepted `header.payload.` (empty third segment) as valid — full auth bypass. |
| **Weak/guessable HMAC secret** | Multiple writeups (e.g. "$dd56a07b5c92" case) | HS256 secret was a common/weak string; cracked offline with a small wordlist, then used to forge admin tokens. |

### What to actually do
1. Decode the token (no signature check needed) — look at `alg` and the
   claims. Note any privilege-looking claim (`role`, `isAdmin`, `scope`).
2. Run `jwt_probe.py --token <captured token>` — it prints:
   - the `alg=none` variant
   - the signature-stripped variant
   - weak-secret guesses against a small built-in list (extend with
     `--wordlist`)
   - if you have the server's RSA public key (often exposed at a JWKS
     endpoint like `/.well-known/jwks.json`), the alg-confusion variant
3. Send each variant manually (curl/Repeater) to an endpoint that should
   require valid auth, and check if it's accepted.
4. If none of the automated variants work, that's still useful —
   move on to session-based checks below rather than brute-forcing further.

## Session / password-reset / MFA logic (non-JWT)

These require understanding the app's actual flow — no script substitutes
for reading the requests in a proxy and thinking through what *should* be
impossible.

| Pattern | Disclosed example | What happened |
|---|---|---|
| **Reset token survives email change** | "Pre-ATO" writeup | A password-reset token stayed valid even after the associated email address was changed, and could be reused long after issuance without re-validating ownership. |
| **Reset token not actually checked** | Writeup example | Removing the reset token parameter entirely from the request was accepted — the server didn't verify its presence, just processed the reset. |
| **MFA step skippable by direct URL** | "$8,500 MFA bypass" writeup | Flawed reset-token validation let a researcher skip straight to the post-MFA state by mapping backend state transitions, bypassing MFA entirely for corporate account takeover. |
| **Race condition across concurrent OTP requests** | E-commerce OTP writeup | Changing the email bound to a login flow *after* the OTP was generated, combined with multi-threaded backend OTP validation, let an attacker bind a victim's OTP-verified session to an attacker-controlled email. |
| **Reset-token TOCTOU race** | Race-condition writeup | Requesting a password reset for your own account and immediately requesting one for a victim's username in the same session window exploited a check/use race to hijack the flow. |
| **Token leaked via logs/referer/analytics** | "Token leakage" writeup | Reset token ended up in a Referer header or third-party analytics call, requiring no more than the attacker seeing it once — no old password or email access needed. |

### What to actually check, per flow
- **Password reset:** Is the token single-use? Time-limited? Long/random
  enough to not be guessable? Does it get invalidated by a *newer* reset
  request? Does removing/blanking the token param still work? Does the
  token leak anywhere (URL in Referer, logs, third-party scripts loaded
  on the reset page)?
- **MFA:** Can you reach the post-MFA authenticated state by directly
  requesting the endpoint the app redirects to after MFA succeeds,
  skipping the MFA submission step?
- **Session:** Does the session ID rotate after login (session fixation
  check)? Does logout actually invalidate server-side state, or just
  clear a client cookie?
- **Race conditions:** For any flow with two steps separated by a
  server round-trip (OTP generation → OTP validation, reset request →
  reset confirmation), try firing the second step multiple times
  concurrently, or interleaving two different flows (e.g. your own and a
  victim's) in the same time window.

## Reporting note
Auth bypass findings are usually Critical/High — but only if you can show
**complete** bypass (reaching an authenticated action with no valid
credentials), not just "the token looks weak." Always demonstrate the full
chain: forged/tampered token → accepted by server → unauthorized action
performed, with the actual request/response.
