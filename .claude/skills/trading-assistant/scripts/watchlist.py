"""Screen liquid NSE stocks for intraday: turnover, daily range (ATR%), price filter, prior-day levels.

  python watchlist.py [--max-price 1500] [--min-turnover-cr 300] [--top 5] [SYMBOL ...]

Needs: pip install yfinance pandas. Uses Yahoo daily bars ('.NS' tickers). Data may lag one day.
"""
import argparse

import pandas as pd
import yfinance as yf

DEFAULT = ("RELIANCE HDFCBANK ICICIBANK INFY TCS SBIN AXISBANK KOTAKBANK LT ITC BHARTIARTL "
           "TATASTEEL JSWSTEEL HINDALCO ONGC NTPC POWERGRID COALINDIA BAJFINANCE MARUTI M&M WIPRO "
           "HCLTECH ADANIPORTS ADANIENT ETERNAL BEL HAL IRCTC PNB BANKBARODA").split()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("symbols", nargs="*")
    ap.add_argument("--max-price", type=float, default=1500)
    ap.add_argument("--min-turnover-cr", type=float, default=300)
    ap.add_argument("--top", type=int, default=5)
    a = ap.parse_args()
    syms = a.symbols or DEFAULT

    d = yf.download([s + ".NS" for s in syms], period="3mo", interval="1d", progress=False,
                    auto_adjust=True, group_by="ticker", threads=True)
    rows = []
    for s in syms:
        try:
            df = d[s + ".NS"].dropna()
            if len(df) < 30:
                continue
            c = df.Close
            tr = pd.concat([df.High - df.Low, (df.High - c.shift()).abs(),
                            (df.Low - c.shift()).abs()], axis=1).max(axis=1)
            atr, px = tr.rolling(14).mean().iloc[-1], c.iloc[-1]
            rows.append({"symbol": s, "close": round(px, 1), "atr_rs": round(atr, 1),
                         "atr_pct": round(100 * atr / px, 2),
                         "turnover_cr": round((c * df.Volume).tail(20).mean() / 1e7),
                         "chg5d_pct": round(100 * (px / c.iloc[-6] - 1), 1),
                         "prev_high": round(df.High.iloc[-1], 1), "prev_low": round(df.Low.iloc[-1], 1),
                         "as_of": str(df.index[-1].date())})
        except Exception:
            continue   # delisted / renamed symbols just drop out
    r = pd.DataFrame(rows)
    if r.empty:
        raise SystemExit("No data returned. Check network access or symbols.")
    r = r[(r.turnover_cr >= a.min_turnover_cr) & (r.close <= a.max_price)]
    r = r[r.atr_pct.between(1.2, 3.5)].sort_values("atr_pct", ascending=False).head(a.top)
    print(r.to_string(index=False))
    print("\nThis is a liquidity/volatility screen, not a directional call. Levels are from the last "
          "available session (as_of).")


if __name__ == "__main__":
    main()
