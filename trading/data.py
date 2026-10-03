"""Download and cache intraday bars from Yahoo Finance (5m bars, last ~60 days).

Usage: python data.py SPY QQQ AAPL
Writes data/<TICKER>.csv with columns datetime, open, high, low, close, volume
(timestamps in exchange-local time, tz stripped, so session filters like 09:30 work).
"""
import sys
from pathlib import Path

import pandas as pd
import yfinance as yf

DATA_DIR = Path(__file__).parent / "data"


def fetch(ticker: str, period: str = "60d", interval: str = "5m") -> pd.DataFrame:
    df = yf.download(ticker, period=period, interval=interval, progress=False, auto_adjust=True)
    if df.empty:
        raise ValueError(f"no data for {ticker}")
    if isinstance(df.columns, pd.MultiIndex):
        df.columns = df.columns.get_level_values(0)
    df.columns = [c.lower() for c in df.columns]
    df.index = df.index.tz_localize(None) if df.index.tz is None else df.index.tz_convert(df.index.tz).tz_localize(None)
    df.index.name = "datetime"
    return df[["open", "high", "low", "close", "volume"]].dropna()


def save(ticker: str, **kw) -> Path:
    DATA_DIR.mkdir(exist_ok=True)
    path = DATA_DIR / f"{ticker.upper()}.csv"
    fetch(ticker, **kw).to_csv(path)
    return path


if __name__ == "__main__":
    for t in sys.argv[1:] or ["SPY"]:
        print(save(t))
