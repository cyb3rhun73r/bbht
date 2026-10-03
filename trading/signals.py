"""Buy/sell signal analyser: composite score from trend, VWAP, momentum and breakout.

  python signals.py backtest SPY QQQ AAPL     # chronological in-sample / out-of-sample report
  python signals.py live SPY AAPL             # latest BUY / SELL / HOLD with stop and target

Score (each +1 bullish / -1 bearish):
  EMA9 vs EMA21 trend, close vs session VWAP, RSI(14) momentum zone,
  breakout of the prior `lookback` bars' high/low.
BUY at score >= threshold, SELL at <= -threshold. Stop = atr_mult * ATR, target = rr * stop.
"""
import argparse
from dataclasses import dataclass

import numpy as np
import pandas as pd

import data


@dataclass
class Params:
    capital: float = 5000.0
    threshold: int = 3
    lookback: int = 12
    atr_mult: float = 1.5
    rr: float = 2.0
    risk_pct: float = 0.005
    max_leverage: float = 2.0
    cost_pct: float = 0.0005
    max_trades_day: int = 2
    skip_first_bars: int = 3       # let the open settle (15 min)
    last_entry: str = "15:00"
    session_end: str = "15:55"


def add_indicators(df: pd.DataFrame, p: Params) -> pd.DataFrame:
    df = df.copy()
    day = df.index.date
    typical = (df.high + df.low + df.close) / 3
    pv = (typical * df.volume).groupby(day).cumsum()
    df["vwap"] = pv / df.volume.groupby(day).cumsum()
    df["ema_fast"] = df.close.ewm(span=9, adjust=False).mean()
    df["ema_slow"] = df.close.ewm(span=21, adjust=False).mean()
    delta = df.close.diff()
    gain = delta.clip(lower=0).ewm(alpha=1 / 14, adjust=False).mean()
    loss = (-delta.clip(upper=0)).ewm(alpha=1 / 14, adjust=False).mean()
    df["rsi"] = 100 - 100 / (1 + gain / loss.replace(0, np.nan))
    tr = pd.concat([df.high - df.low, (df.high - df.close.shift()).abs(),
                    (df.low - df.close.shift()).abs()], axis=1).max(axis=1)
    df["atr"] = tr.ewm(alpha=1 / 14, adjust=False).mean()
    prior_hi = df.high.shift(1).rolling(p.lookback).max()
    prior_lo = df.low.shift(1).rolling(p.lookback).min()
    df["score"] = (
        np.sign(df.ema_fast - df.ema_slow)
        + np.sign(df.close - df.vwap)
        + np.where(df.rsi.between(50, 70), 1, np.where(df.rsi.between(30, 50), -1, 0))
        + np.where(df.close > prior_hi, 1, np.where(df.close < prior_lo, -1, 0))
    )
    return df


def backtest(df: pd.DataFrame, p: Params) -> pd.DataFrame:
    df = add_indicators(df, p)
    equity, trades = p.capital, []
    for day, bars in df.groupby(df.index.date):
        bars = bars.between_time("09:30", p.session_end).dropna(subset=["score", "atr", "rsi"])
        n, i, count = len(bars), p.skip_first_bars, 0
        while i < n - 1 and count < p.max_trades_day:
            row = bars.iloc[i]
            if bars.index[i].strftime("%H:%M") > p.last_entry:
                break
            side = 1 if row.score >= p.threshold else -1 if row.score <= -p.threshold else 0
            if not side:
                i += 1
                continue
            entry = bars.iloc[i + 1].open
            risk = p.atr_mult * row.atr
            stop, target = entry - side * risk, entry + side * p.rr * risk
            qty = min(equity * p.risk_pct / risk, equity * p.max_leverage / entry)
            exit_px, j = bars.iloc[-1].close, n - 1
            for j in range(i + 1, n):
                b = bars.iloc[j]
                hit_stop = b.low <= stop if side == 1 else b.high >= stop
                hit_tgt = b.high >= target if side == 1 else b.low <= target
                if hit_stop:               # stop first when both hit (conservative)
                    exit_px = stop; break
                if hit_tgt:
                    exit_px = target; break
            else:
                j = n - 1
            pnl = side * (exit_px - entry) * qty - p.cost_pct * entry * qty
            equity += pnl
            trades.append({"date": day, "side": side, "pnl": pnl, "equity": equity})
            count += 1
            i = j + 1
    return pd.DataFrame(trades)


def stats(t: pd.DataFrame) -> dict:
    if t.empty:
        return {"trades": 0}
    w, l = t[t.pnl > 0].pnl.sum(), -t[t.pnl <= 0].pnl.sum()
    return {"trades": len(t), "win%": round(100 * (t.pnl > 0).mean(), 1),
            "PF": round(w / l, 2) if l else float("inf"),
            "expect": round(t.pnl.mean(), 2), "pnl": round(t.pnl.sum(), 2)}


def cmd_backtest(tickers, p):
    rows = []
    for tk in tickers:
        df = data.fetch(tk)
        days = sorted(set(df.index.date))
        cut = days[int(len(days) * 2 / 3)]
        a = backtest(df[df.index.date < cut], p)
        b = backtest(df[df.index.date >= cut], p)
        rows.append({"ticker": tk, **{f"IS_{k}": v for k, v in stats(a).items()},
                     **{f"OOS_{k}": v for k, v in stats(b).items()}})
    out = pd.DataFrame(rows).set_index("ticker")
    print(out.to_string())
    for tag in ("IS", "OOS"):
        print(f"\n{tag} total pnl: {out[f'{tag}_pnl'].sum():.2f} on {int(out[f'{tag}_trades'].sum())} trades")


def cmd_live(tickers, p):
    for tk in tickers:
        df = add_indicators(data.fetch(tk, period="5d"), p).dropna(subset=["score", "atr"])
        r = df.iloc[-1]
        action = "BUY" if r.score >= p.threshold else "SELL" if r.score <= -p.threshold else "HOLD"
        line = f"{tk:6} {df.index[-1]}  px={r.close:.2f}  score={int(r.score):+d}  rsi={r.rsi:.0f}  -> {action}"
        if action != "HOLD":
            s = 1 if action == "BUY" else -1
            risk = p.atr_mult * r.atr
            qty = int(min(p.capital * p.risk_pct / risk, p.capital * p.max_leverage / r.close))
            line += f"  stop={r.close - s * risk:.2f} target={r.close + s * p.rr * risk:.2f} qty={qty}"
        print(line)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["backtest", "live"])
    ap.add_argument("tickers", nargs="+")
    ap.add_argument("--threshold", type=int, default=3)
    ap.add_argument("--capital", type=float, default=5000)
    a = ap.parse_args()
    p = Params(capital=a.capital, threshold=a.threshold)
    {"backtest": cmd_backtest, "live": cmd_live}[a.cmd](a.tickers, p)
