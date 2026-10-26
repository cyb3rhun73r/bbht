# Rate-Limit / Brute-Force Bypass — Real Disclosed-Report Pattern Library

Missing or bypassable rate limiting on auth-sensitive endpoints is one of
the fastest, most repeatable findings once you know the bypass
techniques — the same handful of tricks work across most targets. Drawn
from disclosed HackerOne reports.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **No rate limit at all on OTP submission** | MTN Group (H1 #1060541, #1060518) | `https://mtnonline.com/nim/submit` had zero rate-limit protection on OTP code submission — straightforward brute force of a typically 4-6 digit code. |
| **No rate limit on password reset** | Infogram (H1 #280389) | Password-reset endpoint accepted unlimited attempts — relevant both for brute-forcing a reset token and for spamming reset emails as harassment/DoS. |
| **Rate limit bypassed via IP-rotation header** | Mail.ru (multiple reports) | Adding `X-Forwarded-For` (or `X-Real-IP`, `X-Originating-IP`, `Client-IP`) with a different spoofed IP value on each request bypassed IP-based rate limiting, because the app trusted the client-supplied header as the "real" client IP instead of the actual TCP connection source. |
| **$12,000 2FA bypass** | Writeup example | A flawed 2FA code-verification endpoint allowed enough attempts, combined with a bypass technique, to brute-force a 6-digit 2FA code well within a feasible attempt budget. |

## Fast test approach

1. **Identify targets**: login, OTP/2FA submission, password reset
   request + password reset confirmation, email-change confirmation,
   coupon/referral code redemption, any endpoint gated by a short
   numeric code.
2. **Confirm absence of a limit** (gently — a handful of requests is
   enough to tell, don't hammer production auth infra):
   - Send the same request 10-20 times in a row with an intentionally
     wrong code and watch for a lockout, CAPTCHA, or increasing delay.
   - If none appears, that alone is often reportable (Medium severity) —
     you don't need to fully brute-force the code to prove the gap
     exists in most programs, but check the specific program's policy on
     what proof they require.
3. **If a limit does exist, try these bypasses** (each is a real,
   repeatedly-seen pattern across disclosed reports):
   ```
   X-Forwarded-For: 1.2.3.4       (change value per request)
   X-Real-IP: 1.2.3.4
   X-Originating-IP: 1.2.3.4
   X-Client-IP: 1.2.3.4
   X-Remote-IP: 1.2.3.4
   X-Remote-Addr: 1.2.3.4
   Forwarded: for=1.2.3.4
   ```
   Rotate the IP value (increment or randomize) on each request — if the
   lockout counter resets or never triggers, the app is trusting a
   spoofable header for rate-limit keying instead of the real connection
   source.
4. **Other bypass angles to try:**
   - Case variation or trailing whitespace/null-byte on the username/email
     field — some rate limiters key on exact string match and miss
     `user@test.com` vs `User@test.com` vs `user@test.com ` as "different"
     accounts.
   - Race condition: fire several attempts concurrently (not sequentially)
     — some rate limiters check-then-increment in a way that a burst of
     simultaneous requests can slip past before the counter updates.
   - Different endpoint achieving the same action — e.g. if `/api/v1/login`
     is rate-limited but `/api/v2/login` or a mobile-app-specific endpoint
     isn't, the underlying account is still brute-forceable.
   - Resetting the counter via a legitimate action (e.g. some apps reset
     a failed-attempt counter when the *correct* password/code is entered
     anywhere in the flow, or when a new session/token is requested) —
     check if requesting a fresh OTP/token also resets your attempt budget.

## Calculating actual exploitability (for your report)
Don't just claim "no rate limit" — do the impact math:
- OTP/2FA code space (e.g. 6 digits = 1,000,000 possibilities) ÷ realistic
  requests-per-second achievable (often 10-50/sec even unthrottled,
  network-dependent) = real-world time-to-brute-force. State this
  explicitly in the report ("a 6-digit code can be exhausted in under an
  hour at 50 req/s with no lockout") — it's what turns a vague
  "missing rate limit" into a concrete, high-confidence Critical/High
  finding with a triager who doesn't have to do the math themselves.
- Tools: Burp Intruder (with header rotation via a payload list for
  X-Forwarded-For), or a small custom script when precise timing/threading
  control is needed. Always respect the program's stated rate-limit
  testing policy — some explicitly cap how many attempts you're allowed
  to send during testing.
