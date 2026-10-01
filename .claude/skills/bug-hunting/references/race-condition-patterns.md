# Race Conditions (TOCTOU) — Real Disclosed-Report Pattern Library

A race condition exploits the gap between when an app *checks* something
(is this coupon unused? does this account have enough balance?) and when
it *acts* on that check (mark coupon used, deduct balance) — fire enough
requests in that gap simultaneously and the check passes multiple times
before any of them finish updating state. Low technical complexity, high
payout, and surprisingly common because almost no backend developer tests
concurrent request handling by default.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Coupon/discount redeemed multiple times** | Instacart (H1 #157996) | A single-use coupon could be redeemed repeatedly by landing multiple requests inside the validate→mark-used window, stacking savings far beyond the intended discount. |
| **Gift card redeemed multiple times** | Reverb.com (H1 #759247, $1,500) | Same TOCTOU pattern applied to gift-card redemption instead of a coupon. |
| **Paid multiple times for one action** | HackerOne's own platform (H1 #429026, $2,100) | Firing multiple concurrent requests to confirm a retest let a malicious user get paid multiple times for what should have been a single retest action — shows this pattern applies to *any* "do X once, get rewarded" flow, not just e-commerce discounts. |
| **Unlimited fee-free transactions** | Stripe-adjacent disclosed writeup ($5,000) | A fee-discount could be redeemed multiple times via the same race pattern, netting unlimited fee-free transactions rather than a one-time discount. |

## Fast test approach
1. **Identify candidate endpoints**: anything with a "do this once" or
   "check balance/limit then act" semantic — coupon/discount redemption,
   gift card redemption, referral bonus claiming, free-trial activation,
   withdrawal/transfer requests, vote/like/follow actions with a
   once-per-user limit, API rate-limited actions themselves.
2. **Fire the same request multiple times concurrently** (not
   sequentially — the whole point is overlapping the check-then-act
   window):
   - Burp Suite's **Repeater "Send group in parallel"** (modern Burp) or
     the **Turbo Intruder** extension (`race_condition` template) are
     purpose-built for this — they synchronize request dispatch to land
     in the same tiny window.
   - A simple script firing 10-20 identical requests via concurrent
     threads/async works when a dedicated tool isn't available:
     ```python
     import asyncio, httpx
     async def fire(client, url, headers, body):
         return await client.post(url, headers=headers, json=body)
     async def race(url, headers, body, n=20):
         async with httpx.AsyncClient() as client:
             tasks = [fire(client, url, headers, body) for _ in range(n)]
             return await asyncio.gather(*tasks)
     ```
3. **Check the outcome**: did the coupon apply more than once? Did the
   balance go negative? Did the one-time action succeed more than once?
   Compare against doing it normally (one request, one success) to
   confirm the race actually changed behavior.
4. **Widen the window if the race doesn't land on the first try**: some
   backends are fast enough that even 20 concurrent requests rarely
   overlap the vulnerable window. Techniques to improve odds:
   - **Single-packet attack / last-byte sync** (used by Turbo Intruder's
     advanced mode): hold back the final bytes of several HTTP/1.1
     requests on already-open connections, then release them all at
     once, so they arrive at the server in the same instant rather than
     being staggered by normal TCP/TLS handshake timing.
   - Target an action known to have extra processing time server-side
     (e.g. one that calls a slow downstream service) — a larger
     check-to-act window is easier to land a race in.
5. **Also check cross-request races**, not just same-endpoint repeats:
   e.g. firing a "cancel order" and "ship order" request simultaneously,
   or "delete account" and "transfer funds" — some of the highest-value
   race conditions are between two *different* endpoints that share
   underlying state but don't coordinate locking between each other.

## Why this is worth your time specifically
Race conditions need no custom payload crafting (same request, just
concurrent) and most backends have never been load-tested for this
specific failure mode, so the hit rate on "do once" financial/limit
actions is genuinely good. The downside is some backends are fast enough
that landing the race takes several attempts — budget for that rather
than concluding "not vulnerable" after one try.
