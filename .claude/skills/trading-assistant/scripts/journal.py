"""Trade journal (CSV) with honest stats.

  python journal.py add --symbol ETERNAL --side long --qty 4 --entry 321 --exit 326 --stop 316 \
        --followed y --reason "ORB above PDH, VWAP up" --emotion calm [--file trading_journal.csv]
  python journal.py stats [--file trading_journal.csv]

pnl_net = gross P&L minus approximate NSE intraday costs (see position_size.costs).
"""
import argparse
import csv
import os
from datetime import date

import pandas as pd

from position_size import costs

FIELDS = ["date", "symbol", "side", "qty", "entry", "exit", "stop", "pnl_net", "r_multiple",
          "followed_rules", "emotion", "reason"]


def add(a):
    s = 1 if a.side == "long" else -1
    buy, sell = (a.entry, a.exit) if s == 1 else (a.exit, a.entry)
    pnl = s * (a.exit - a.entry) * a.qty - costs(a.qty, buy, sell)
    risk = abs(a.entry - a.stop) * a.qty if a.stop else None
    row = {"date": a.date or date.today().isoformat(), "symbol": a.symbol, "side": a.side,
           "qty": a.qty, "entry": a.entry, "exit": a.exit, "stop": a.stop or "",
           "pnl_net": round(pnl, 2), "r_multiple": round(pnl / risk, 2) if risk else "",
           "followed_rules": a.followed, "emotion": a.emotion or "", "reason": a.reason or ""}
    new = not os.path.exists(a.file)
    with open(a.file, "a", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        if new:
            w.writeheader()
        w.writerow(row)
    print(f"Logged {a.symbol} {a.side}: net P&L Rs{pnl:,.2f}")


def stats(a):
    t = pd.read_csv(a.file)
    n = len(t)
    wins, losses = t[t.pnl_net > 0], t[t.pnl_net <= 0]
    pf = wins.pnl_net.sum() / abs(losses.pnl_net.sum()) if losses.pnl_net.sum() else float("inf")
    print(f"Trades: {n}   Net P&L: Rs{t.pnl_net.sum():,.2f}")
    print(f"Win rate: {100 * len(wins) / n:.0f}%   Avg win: {wins.pnl_net.mean() if len(wins) else 0:.2f}"
          f"   Avg loss: {losses.pnl_net.mean() if len(losses) else 0:.2f}")
    print(f"Profit factor: {pf:.2f}   Expectancy/trade: Rs{t.pnl_net.mean():.2f}")
    f = t.followed_rules.astype(str).str.lower().str.startswith("y")
    print(f"Rules followed: {100 * f.mean():.0f}% of trades")
    if f.any() and (~f).any():
        print(f"  P&L when followed: Rs{t[f].pnl_net.sum():,.2f}   when broken: Rs{t[~f].pnl_net.sum():,.2f}")
    if n < 30:
        print(f"\nOnly {n} trades. Under ~30 the numbers are mostly noise; don't draw conclusions yet.")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add")
    p.add_argument("--symbol", required=True)
    p.add_argument("--side", choices=["long", "short"], required=True)
    p.add_argument("--qty", type=int, required=True)
    p.add_argument("--entry", type=float, required=True)
    p.add_argument("--exit", type=float, required=True)
    p.add_argument("--stop", type=float)
    p.add_argument("--followed", choices=["y", "n"], required=True)
    p.add_argument("--reason")
    p.add_argument("--emotion")
    p.add_argument("--date")
    p.add_argument("--file", default="trading_journal.csv")
    p.set_defaults(fn=add)
    q = sub.add_parser("stats")
    q.add_argument("--file", default="trading_journal.csv")
    q.set_defaults(fn=stats)
    a = ap.parse_args()
    a.fn(a)
