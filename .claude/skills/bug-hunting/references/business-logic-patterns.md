# Business Logic Flaws — Real Disclosed-Report Pattern Library

The highest ceiling in this entire skill. No scanner finds these — they
require understanding what a checkout, trading, or workflow process is
*supposed* to do, then finding the step where the app trusts a value it
shouldn't. Per HackerOne's own data: the payout gap between a routine
SQLi ($5,000) and a well-found price-manipulation bug ($25,000) shows how
disproportionately these pay relative to the technical difficulty —
usually no exploit chain, just noticing an assumption the backend didn't
actually enforce. One example below paid **$250,000**.

## Where disclosed reports actually found it

| Pattern | Disclosed example | Detail |
|---|---|---|
| **Negative-quantity price manipulation** | OLO | Adding an item with a *negative* quantity to an order directly manipulated the total — the backend summed `price × quantity` per line item without validating quantity couldn't go negative, so one negative-quantity line item subtracted from the total. |
| **Coupon + cart-edit ordering flaw** | Shopify merchant disclosure | Applying a coupon, *then* editing cart quantities after the coupon was applied, produced a final price that was neither the correctly-discounted total nor the pre-coupon total — the discount was computed once and never recalculated against the edited cart, letting a $100 cart be bought for under $15. |
| **Discount redeemed beyond intended limit** | Stripe-adjacent disclosed writeup ($5,000) | A fee discount meant to apply once could be redeemed repeatedly (this overlaps with race conditions — see `race-condition-patterns.md` — but the root cause here is business-logic: no server-side tracking of "has this discount already been used on this account" at all, race or no race). |
| **Cross-asset balance confusion** | Coinbase Advanced Trading API ($250,000, Critical) | The API let a user manipulate requests to trade one cryptocurrency using the *balance of a different asset* — the trading-pair validation didn't actually bind the balance check to the specific asset being traded, so a request could reference one asset's balance while executing a trade in another. The sheer bounty size reflects both the severity (real financial loss at scale) and how non-obvious the flaw was — no obvious single "bug," just a mismatch between which value validated and which value executed. |
| **Non-premium feature access via logic flaw** | Curve (H1 #672487) | A non-premium user could access premium-gated functionality — the general "paid feature gate checks the wrong thing" pattern, common wherever a frontend hides a feature but the backend doesn't independently re-verify entitlement. |

## Common root-cause shapes (recognize these, and you'll find these bugs)
1. **Value computed once, trusted forever** — a price, discount, or total
   calculated at step N of a multi-step flow, then never recalculated or
   re-validated at step N+1 even though the cart/order/state changed.
   *Test:* at every multi-step flow (cart → coupon → edit → checkout),
   try reordering or repeating a step out of sequence.
2. **Quantity/amount fields trusted without a sane-bounds check** — no
   validation that quantity ≥ 0, that a transfer amount doesn't exceed
   balance, that a rating is within 1-5.
   *Test:* submit negative numbers, zero, extremely large numbers,
   decimals where an integer is expected, in any quantity/amount/price
   field — even ones the UI doesn't expose as editable (check the raw
   request body).
3. **Entitlement/permission check happens client-side or once, not
   re-verified server-side at the point of action** — a "premium" flag
   checked when a page loads, but not re-checked when the actual
   privileged action is performed moments later via API.
   *Test:* access the premium/gated action's API endpoint directly,
   bypassing whatever UI flow normally gates it.
4. **A value used for validation isn't the same value used for
   execution** — the Coinbase pattern: one field determines what's
   "allowed," a different field determines what actually happens, and
   nothing binds them together.
   *Test:* in any multi-parameter request (asset + amount, item +
   price, from-account + to-account), try mismatching the parameters —
   change one without the other and see if the app executes the
   mismatched combination instead of rejecting it.
5. **Workflow step skipped or reordered** — a step the UI enforces in
   order (verify email → set password → access dashboard) isn't
   independently enforced by the backend at each stage.
   *Test:* call step 3's API directly without having completed step 1/2;
   replay an earlier step's request after a later step has already run.

## Fast test approach
1. Map every multi-step flow on the target: checkout, signup,
   subscription upgrade/downgrade, trading/transfer, referral/reward
   claiming, content moderation/approval workflows.
2. For each, write down what the app is *supposed* to prevent at each
   step (negative amounts, reordering, skipping, mismatched values) —
   then try exactly that.
3. Always inspect the raw request body, not just the UI — many of these
   bugs only show up when you edit a field the UI never exposes (a
   hidden `price` field sent alongside a `product_id`, a `quantity` the
   UI only lets you increment but the API accepts any integer).
4. Chain with other classes in this skill: a business-logic flaw often
   combines with IDOR (manipulate *your own* order logic, but on
   someone else's account/order — see `idor-bola-patterns.md`) or with
   race conditions (an intended-once action, exploited via concurrency
   as well as via logic — see `race-condition-patterns.md`).
5. Document business-impact precisely in your report — "I can buy a
   $100 item for $15" or "I can trade using another asset's balance" is
   a much stronger, more specific impact statement than "business logic
   flaw," and is what justifies the outsized payouts this class gets.
