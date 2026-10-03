"""Intraday backtester: Opening Range Breakout (ORB) + VWAP trend filter.

Input: CSV of intraday bars (e.g. 5-minute) with columns:
    datetime, open, high, low, close, volume
Usage:
    python backtest.py data.csv --capital 5000
    python backtest.py --synthetic            # pipeline test only, results are meaningless

Rules (all configurable below):
  * Opening range = first `or_minutes` of the session.
  * Long when price closes above OR high AND above VWAP; short mirror image.
  * Stop = opposite side of the OR (capped by max stop %), target = rr * risk.
  * Position size = risk_pct of current equity / per-share risk (no leverage beyond max_leverage).
  * One trade per day, force-exit at the session end (intraday only).
  * Daily loss limit and costs/slippage are modelled.
"""
import argparse
from dataclasses import dataclass

import numpy as np
import pandas as pd


@dataclass
class Config:
    capital: float = 5000.0
    or_minutes: int = 15           # opening range length
    rr: float = 2.0                # reward : risk
    risk_pct: float = 0.01         # risk 1% of equity per trade
    max_leverage: float = 2.0      # cap on notional / equity
    max_stop_pct: float = 0.01     # skip days where the OR is wider than 1% of price
    cost_pct: float = 0.0005       # round-trip commission + slippage (0.05%)
    daily_loss_limit: float = 0.02  # stop trading for the day at -2%
    session_start: str = "09:30"
    session_end: str = "15:55"     # flatten here


def load_csv(path: str) -> pd.DataFrame:
    df = pd.read_csv(path, parse_dates=["datetime"]).set_index("datetime").sort_index()
    df.columns = [c.lower() for c in df.columns]
    return df[["open", "high", "low", "close", "volume"]]


def synthetic(days: int = 120, seed: int = 7) -> pd.DataFrame:
    """Random-walk 5-min bars. A random walk has NO edge: expect ~zero/negative result after costs."""
    rng = np.random.default_rng(seed)
    frames, price = [], 100.0
    for d in pd.bdate_range("2024-01-02", periods=days):
        idx = pd.date_range(d + pd.Timedelta(hours=9, minutes=30), d + pd.Timedelta(hours=15, minutes=55), freq="5min")
        ret = rng.normal(0, 0.0012, len(idx))
        close = price * np.exp(np.cumsum(ret))
        open_ = np.r_[price, close[:-1]]
        spread = np.abs(rng.normal(0, 0.0007, len(idx))) * close
        frames.append(pd.DataFrame({
            "open": open_, "high": np.maximum(open_, close) + spread,
            "low": np.minimum(open_, close) - spread,
            "close": close, "volume": rng.integers(1_000, 10_000, len(idx)),
        }, index=idx))
        price = close[-1]
    return pd.concat(frames)


def run(df: pd.DataFrame, cfg: Config) -> pd.DataFrame:
    equity, trades = cfg.capital, []
    for day, bars in df.groupby(df.index.date):
        bars = bars.between_time(cfg.session_start, cfg.session_end)
        if len(bars) < 10:
            continue
        typical = (bars.high + bars.low + bars.close) / 3
        vwap = (typical * bars.volume).cumsum() / bars.volume.cumsum()

        start = bars.index[0]
        orb = bars[bars.index < start + pd.Timedelta(minutes=cfg.or_minutes)]
        hi, lo = orb.high.max(), orb.low.min()
        rest = bars[bars.index >= start + pd.Timedelta(minutes=cfg.or_minutes)]
        if rest.empty or (hi - lo) / hi > cfg.max_stop_pct:
            continue

        side = entry = stop = target = None
        for ts, bar in rest.iterrows():
            if side is None:
                # signal on bar close, enter at the next bar's open to avoid look-ahead
                if bar.close > hi and bar.close > vwap[ts]:
                    side = 1
                elif bar.close < lo and bar.close < vwap[ts]:
                    side = -1
                if side:
                    nxt = rest.index.get_loc(ts) + 1
                    if nxt >= len(rest):
                        break
                    entry = rest.iloc[nxt].open
                    stop = lo if side == 1 else hi
                    risk = abs(entry - stop)
                    if risk <= 0:
                        side = None
                        continue
                    target = entry + side * cfg.rr * risk
                    qty = min(equity * cfg.risk_pct / risk, equity * cfg.max_leverage / entry)
                    entry_ts = rest.index[nxt]
                continue
            if ts < entry_ts:
                continue
            exit_px = None
            # conservative: if both hit in one bar, assume stop first
            if side == 1:
                if bar.low <= stop: exit_px = stop
                elif bar.high >= target: exit_px = target
            else:
                if bar.high >= stop: exit_px = stop
                elif bar.low <= target: exit_px = target
            if exit_px is None and ts == rest.index[-1]:
                exit_px = bar.close
            if exit_px is not None:
                pnl = side * (exit_px - entry) * qty - cfg.cost_pct * entry * qty
                pnl = max(pnl, -cfg.daily_loss_limit * equity) if cfg.daily_loss_limit else pnl
                equity += pnl
                trades.append({"date": day, "side": side, "entry": entry, "exit": exit_px,
                               "qty": qty, "pnl": pnl, "equity": equity})
                break
    return pd.DataFrame(trades)


def report(t: pd.DataFrame, cfg: Config) -> None:
    if t.empty:
        print("No trades.")
        return
    wins = t[t.pnl > 0]
    losses = t[t.pnl <= 0]
    peak = t.equity.cummax()
    dd = ((t.equity - peak) / peak).min()
    pf = wins.pnl.sum() / abs(losses.pnl.sum()) if len(losses) and losses.pnl.sum() else float("inf")
    daily = t.pnl / t.equity.shift(1).fillna(cfg.capital)
    sharpe = daily.mean() / daily.std() * np.sqrt(252) if daily.std() > 0 else float("nan")
    print(f"Trades:          {len(t)}")
    print(f"Win rate:        {len(wins) / len(t):.1%}")
    print(f"Avg win / loss:  {wins.pnl.mean():.2f} / {losses.pnl.mean():.2f}")
    print(f"Profit factor:   {pf:.2f}")
    print(f"Expectancy/trade:{t.pnl.mean():.2f}")
    print(f"Sharpe (ann.):   {sharpe:.2f}")
    print(f"Max drawdown:    {dd:.1%}")
    print(f"Start -> End:    {cfg.capital:,.0f} -> {t.equity.iloc[-1]:,.0f} "
          f"({t.equity.iloc[-1] / cfg.capital - 1:+.1%})")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("csv", nargs="?")
    ap.add_argument("--synthetic", action="store_true")
    ap.add_argument("--capital", type=float, default=5000)
    ap.add_argument("--rr", type=float, default=2.0)
    ap.add_argument("--risk-pct", type=float, default=0.01)
    ap.add_argument("--or-minutes", type=int, default=15)
    a = ap.parse_args()
    cfg = Config(capital=a.capital, rr=a.rr, risk_pct=a.risk_pct, or_minutes=a.or_minutes)
    data = synthetic() if a.synthetic else load_csv(a.csv)
    report(run(data, cfg), cfg)
