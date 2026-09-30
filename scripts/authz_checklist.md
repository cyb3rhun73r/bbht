# Access Control / Auth Logic Manual Checklist

No scanner reliably finds these -- they require understanding what the
application's workflow is *supposed* to allow, which is exactly why
Improper Access Control and IDOR are currently the highest-paying, most
in-demand bug classes on HackerOne. Use `access_check.py` and
`jwt_probe.py` to generate candidates fast, then work this checklist by
hand on anything flagged (and on anything they miss).

**Only test against programs/assets you have explicit authorization for,
and only using accounts you control or are permitted to test with.**

## 1. Horizontal access (IDOR)
- [ ] Every endpoint that takes an object ID (invoice, order, message,
      document, ticket...) -- swap the ID for one belonging to another
      account. Try sequential IDs, UUIDs (check if they're guessable/leaked
      elsewhere), and IDs from a second test account.
- [ ] Try IDs in every location: URL path, query string, JSON body, and
      **hidden form fields** -- not just the obvious ones.
- [ ] Check GraphQL: object IDs in query variables are a very common miss.
- [ ] Check export/download/PDF-generation endpoints -- often skip the
      authz check the normal view page has.
- [ ] Check "share" or "public link" features -- sometimes the shared link
      exposes more than intended (leaks other fields, or the link itself
      grants edit access instead of view-only).

## 2. Vertical access (privilege escalation)
- [ ] As a low-priv/free-tier user, directly request admin/paid-tier
      routes by URL, even if there's no link to them in the UI.
- [ ] Check every state-changing request the admin UI makes (view page
      source / network tab as admin, then replay with your low-priv
      session).
- [ ] Look for a `role`, `isAdmin`, `user_type`, `plan`, or similar field
      in registration, profile-update, or signup requests -- some apps
      trust client-supplied values here.
- [ ] Mobile app / API-only endpoints often lag behind the web app's
      access control fixes -- test the same actions through the API.

## 3. Missing function-level access control
- [ ] Forced browsing: try admin paths even when not linked
      (`/admin`, `/internal`, `/api/v1/admin/...`, `/debug`, `/_internal`).
- [ ] Check HTTP methods other than the one the UI uses -- an endpoint
      might reject GET as admin-only but still accept POST/PUT/DELETE
      from a lower-priv session.
- [ ] Check versioned/legacy API paths (`/api/v1/` vs `/api/v2/`) -- older
      versions sometimes keep weaker checks.

## 4. Auth / session logic
- [ ] Password reset: is the token single-use? Does it expire? Is it
      predictable (sequential, timestamp-based, short)? Can you reuse an
      old one after requesting a new one?
- [ ] Is there a rate limit on login, OTP, and password-reset endpoints?
      (Test gently -- a handful of attempts is enough to tell; don't
      hammer production auth infra.)
- [ ] Session fixation: does the session ID change after login, or can an
      attacker-set session ID persist post-auth?
- [ ] Logout: does it actually invalidate the token/session server-side,
      or just clear the client-side cookie?
- [ ] "Remember me" tokens -- are they long-lived and still validated
      properly, or a weaker, guessable mechanism?
- [ ] MFA: can it be bypassed by directly hitting the post-MFA endpoint
      after only completing step 1 (password)?
- [ ] OAuth/SSO flows: check `redirect_uri`/`state` handling for open
      redirect or CSRF-into-account-linking issues.

## 5. Business logic (often the highest-value, least-automatable bugs)
- [ ] Can a multi-step process be reordered or a step skipped (e.g. skip
      payment, submit review before verified, approve your own request)?
- [ ] Can quantity/price/discount fields be manipulated client-side before
      submission, even if "validated" on a later screen?
- [ ] Can an action be repeated when it should be one-time (double
      redemption of a coupon, replaying a webhook, resubmitting a form)?

## 6. Workflow for turning a flag into a report
1. Confirm via 2 independent requests (not just one -- rule out caching
   artifacts or a flaky response).
2. Screenshot/log the exact request + response showing the unauthorized
   data or action.
3. Write minimal reproduction steps from a fresh session (no leftover
   cookies/state from your testing).
4. State impact plainly: what data/action was exposed, to whom, and what
   an attacker could do with it.
