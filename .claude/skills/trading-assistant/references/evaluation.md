# Evaluating a strategy honestly

Use this when the user shares backtest or Strategy Tester results, or asks "does this strategy work?".

## Checklist

1. **Costs and slippage included?** NSE intraday: brokerage + STT + exchange/GST/stamp, plus 1-2 ticks slippage. A strategy with a thin edge before costs is usually negative after.
2. **Enough trades?** Under ~100 trades the result is mostly luck; aim for 200+. Say "not enough data" rather than guessing.
3. **Out-of-sample.** Parameters chosen on period A must be tested on later period B that was never used for tuning. Better: walk-forward. A strategy that wins in-sample and loses out-of-sample is overfit.
4. **Across instruments.** An edge on one stock only is likely a fluke. Check several liquid names.
5. **Key numbers.** Profit factor (> ~1.3 net), expectancy per trade after costs (> 0), max drawdown the user can actually tolerate (and relative to Rs-sized capital), win rate only together with average win/loss.
6. **Look-ahead and fill assumptions.** Signals on bar close must enter on the next bar's open; if stop and target hit in the same bar, assume the stop hit first.
7. **Regime.** Did it only work in one trending month? Ask for results by month.

## Verdict wording

- Fails 1-3: "No evidence of an edge yet" - explain which check failed. Do not suggest tweaking parameters to fix it on the same data.
- Passes all: "Worth paper trading for 4-8 weeks", never "ready for real money".
- Suggest testing structurally different ideas on longer data (e.g. mean-reversion vs trend) instead of curve-fitting one.

## Reference result from earlier work

A trend-following score system (EMA, VWAP, RSI, breakout) on ~60 days of 5-minute data for 10 liquid US stocks lost money both in-sample and out-of-sample. That is the kind of result that should be reported as-is.
