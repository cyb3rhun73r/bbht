"""Risk-based position sizing + approximate NSE intraday (MIS equity) costs.

  python position_size.py --capital 2000 --entry 314 --stop 309 [--target 324] [--side long]
                          [--risk-pct 1] [--leverage 5] [--brokerage-pct 0.03]

Costs are approximations (check your broker's contract note): brokerage min(Rs20, pct of turnover)
per order, STT 0.025% on sell, exchange txn ~0.00297%, SEBI 0.0001%, stamp 0.003% on buy, GST 18%
on brokerage + txn + SEBI.
"""
import argparse
import math


def costs(qty, buy_px, sell_px, brokerage_pct=0.03):
    buy, sell = qty * buy_px, qty * sell_px
    brk = min(20, buy * brokerage_pct / 100) + min(20, sell * brokerage_pct / 100)
    txn = 0.0000297 * (buy + sell)
    sebi = 1e-6 * (buy + sell)
    stt = 0.00025 * sell
    stamp = 0.00003 * buy
    gst = 0.18 * (brk + txn + sebi)
    return brk + txn + sebi + stt + stamp + gst


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--capital", type=float, required=True)
    ap.add_argument("--entry", type=float, required=True)
    ap.add_argument("--stop", type=float, required=True)
    ap.add_argument("--target", type=float)
    ap.add_argument("--side", choices=["long", "short"], default="long")
    ap.add_argument("--risk-pct", type=float, default=1.0)
    ap.add_argument("--leverage", type=float, default=5.0)
    ap.add_argument("--brokerage-pct", type=float, default=0.03)
    a = ap.parse_args()

    s = 1 if a.side == "long" else -1
    if (a.entry - a.stop) * s <= 0:
        raise SystemExit("Stop must be below entry for longs / above entry for shorts.")
    risk_per_share = abs(a.entry - a.stop)
    qty = math.floor(min(a.capital * a.risk_pct / 100 / risk_per_share,
                         a.capital * a.leverage / a.entry))
    if qty < 1:
        raise SystemExit("Quantity rounds to 0: stop too wide or price too high for this capital.")
    target = a.target or a.entry + s * 2 * risk_per_share
    px = lambda p: (a.entry, p) if s == 1 else (p, a.entry)   # (buy, sell)
    stop_cost = costs(qty, *px(a.stop), a.brokerage_pct)
    tgt_cost = costs(qty, *px(target), a.brokerage_pct)
    risk = qty * risk_per_share + stop_cost
    reward = qty * abs(target - a.entry) - tgt_cost

    print(f"Side / qty:        {a.side} {qty} shares  (position Rs{qty * a.entry:,.0f}, "
          f"margin ~Rs{qty * a.entry / a.leverage:,.0f})")
    print(f"Stop / target:     {a.stop} / {target:.2f}")
    print(f"Max loss at stop:  Rs{risk:,.2f} incl. costs  ({100 * risk / a.capital:.2f}% of capital)")
    print(f"Gain at target:    Rs{reward:,.2f} net of costs")
    print(f"Net reward:risk:   {reward / risk:.2f}")
    print(f"Costs at target:   Rs{tgt_cost:,.2f}  ({100 * tgt_cost / (qty * a.entry):.3f}% of position)")
    if tgt_cost > 0.25 * qty * abs(target - a.entry):
        print("WARNING: costs eat >25% of the gross target. Trade is likely not worth taking.")
    if risk / a.capital > 0.02:
        print("WARNING: loss at stop exceeds 2% of capital.")


if __name__ == "__main__":
    main()
