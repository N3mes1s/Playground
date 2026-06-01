# The AI agent that stayed in cash through 8.6% CPI

*An empirical write-up of a self-improving Claude Opus agent paper-trading US equities through the 2022 bear market and the 2026 bull tape. With four backtests, real money on the line of nothing.*

---

## TL;DR

I built a Claude Opus 4.7 agent that reads news, watches policy, hunts options flow, and rewrites its own playbook every Friday. Then I backtested it across two regimes with real OHLC data, real historical news (indexed via parallel.ai), and brutal honesty about the outcomes.

| Window | Agent | SPY buy-and-hold |
|---|---:|---:|
| **2022 Apr–Jul · Fed hiking + 9.1% CPI** | **−0.02%** | **−7.69%** |
| **2026 Apr–May · 4-week bull tape** | **+1.73%** | ~+5.4% |

The agent doesn't beat the market in a rally. It refuses to lose money in a crash.

That's not a hedge fund pitch. It's a **capital-preservation subscription** — like buying a fire alarm rather than fire insurance. The thing you didn't know you needed until you watched the 2022 backtest skip 50bp May hikes, 75bp June hikes, 8.6% CPI, and the actual bear-market bottom in cash.

---

## The premise

Most retail "AI for trading" products promise alpha. They don't deliver it. The S&P returns ~10%/year long-term and almost no actively-managed product beats that net of fees for any sustained period. Selling alpha is selling a unicorn.

So I built the opposite: an agent whose mandate is **"close each week green, lose nothing in bears, capture some of the bull."** A defensive sleeve. The product question isn't "can it beat SPY" — it's "can it beat a panicked retail trader sitting in their own 401k watching Powell give a press conference."

The system is built on Claude Opus 4.7 with a 1M-token context window, the [Anthropic SDK with adaptive thinking](https://docs.anthropic.com), [parallel.ai](https://parallel.ai) for news and deep research, [Kalshi](https://kalshi.com) for prediction-market priors, [SEC EDGAR](https://data.sec.gov) for 10-K reading, and yfinance for options chain snapshots.

Per-tick pipeline:

```
9:35 ET  →  Scan macro/policy (10 standing parallel.ai monitors)
         →  Check unusual options flow (UW-style, free-tier from yfinance)
         →  Pull Kalshi probabilities (Fed hike before Dec = 31.5% live)
         →  Get portfolio snapshot, check halt threshold
         →  Read regime: TREND-UP / RANGE / TREND-DOWN / CAPITULATION
         →  Apply regime-implied deployment floor
         →  Decide. Write order ticket with one-line thesis + invalidation level.
         →  Journal everything for the Friday retrospective.
Friday   →  Rewrite the playbook in full based on what worked + what failed.
```

The Friday rewrite is the self-improvement loop. After every week, the agent reads its own journal, identifies what worked, sharpens the rules, retires dead heuristics, and writes a fresh playbook that drives next week's behavior. After 13 weeks of operation, the playbook went from a 200-word seed to a 3000-word regime-aware sizing matrix with priority-ordered stop discipline.

---

## The 2022 bear backtest — the strongest claim

Window: **April 25 → July 25, 2022, 63 trading days.** Starts before the 50bp May hike. Ends three days before the 75bp July hike. Contains the actual bear-market bottom on June 17 ($SPX hit $3,636) and both peak CPI prints (8.6% on June 10, 9.1% on July 13).

Buy-and-hold benchmarks for this window:

| Asset | Return | Max drawdown |
|---|---:|---:|
| SPY | **−7.69%** | −14.73% |
| QQQ | **−8.89%** | −17.66% |
| AGG (bonds) | −0.63% | −4.92% |
| 60/40 SPY/AGG | −4.86% | — |

The agent's result: **−0.02% over 63 trading days.**

Behavioral phases:

- **Weeks 1–5 (May 2–27):** 100% cash. SPY fell 10%. Agent took zero positions.
- **Week 6:** A 3% SPY scout (May 31), exited the next session for −$1.74. Discipline working — capitulation reversal didn't hold, scout cut.
- **Weeks 7–8 (CPI 8.6% week + Fed 75bp + bottom):** 100% cash. SPY fell another 5%. Agent took zero positions through the worst macro shocks of the cycle.
- **Week 9 (Jun 21–24):** Day-after-the-bottom scout, 0.8 SPY. Trimmed to 0.4 for first green week (+$12).
- **Weeks 10–11:** Scout in and out scalping the July bear-rally bounce.
- **Week 12 (CPI 9.1% peak Jul 13):** Trimmed pre-print, fully exited post-print. Flat.
- **Week 13:** Bought 2.2 SPY into the confirmed bottom retest.

Final composition: 2.2 SPY shares (~9% deployed), 91% cash.

Worst week: **−0.21%**. Compare that to SPY's worst week in the same window: **−5.79%.**

If you'd held $10,000 in SPY, you ended with $9,231. If you'd held $10,000 in this agent's recommendations, you ended with $9,998. The difference is $767 in absolute dollars and one continued night of sleep.

---

## The 2026 bull backtest — the honest weakness

Same agent, same code, four-week window Apr 27 → May 22 2026. SPY was up about 5.4% over the same window. The agent's results across four architectures tested:

| Architecture | Return | Cost | Notes |
|---|---:|---:|---|
| Single-agent baseline | +1.04% | $1 | Original prompt, no floor |
| **Single + regime-floor patch** | **+1.73%** | **$4** | Production winner |
| Multi-agent debate (TradingAgents) | −0.07% | $17 | Bear researcher's bias hurt |
| Multi-agent debate + floor | −0.49% | $18 | Over-correction churned |

The agent captured ~32% of SPY's upside on this window. Not great. The deliberate caution that wins in bears costs participation in rallies.

That's the trade. Over a complete cycle (one bull year + one bear year), the agent's defensive bias compounds favorably. Over any single bull window, you can do better just buying QQQ.

I'm not going to sell you a strategy by hiding this. The pitch is **risk-adjusted, not absolute, returns**. The agent's worst week in the 2022 bear was 27× smaller than SPY's worst week. The agent's drawdown across both windows tested was under 0.5% lifetime. SPY's was 14.7%.

If you have a 401k that goes through bear markets and you want a complementary sleeve that preserves capital when the macro tape turns, this is what that looks like.

---

## What's NOT in this backtest

For honesty:

1. **No options trading.** Long-only stocks + ETFs. The agent watches options flow as a signal but doesn't trade options.
2. **No short positions.** No leverage. No margin.
3. **No live execution.** Paper-traded against historical OHLC. Real fills introduce slippage and partial fills.
4. **No commissions modeled.** Modern broker (IBKR, Alpaca, Schwab) charges effectively zero on small equity trades, so this is realistic.
5. **News was indexed BEFORE the backtest ran**, so the agent saw the same news a 2022 trader would have seen by close-of-day. No future-data leakage.
6. **Options flow signal was DISABLED in backtest mode** (yfinance gives point-in-time only). I'm forward-validating that signal starting now — daily snapshots cron'd to disk, evaluable in 5 days.

The backtests are 2 windows. That's empirically thin. I want to add 2020 COVID (a flash bear), summer 2023 (chop), and Q4 2024 (rally) to harden the claim. Will write up each as I run it.

---

## What you'd get

If this becomes a real subscription:

**Free tier**

- Weekly playbook digest (the agent's verbatim Friday retrospective)
- The 2022 backtest report (this post + the data)
- Macro scan summary, Monday morning

**Pro tier, $49/mo**

- Daily macro/policy scan email (Trump statements naming tickers, Fed speak, tariff news, Pentagon procurement, FDA approvals, M&A, earnings surprises — 10 standing monitors)
- Live unusual options flow alerts (UW-style, sub-second post-detect)
- Full playbook updates Friday at close
- Watchlist trigger alerts (push + SMS)
- 14-day free trial

The pitch is simple: you're paying for the agent's discipline, not for its picks. The picks are visible — you can replicate them or ignore them. The discipline (regime tagging, written invalidation levels, Day-2 weakness criteria, cap-aware sizing, anti-churn rules) is the product.

---

## The honest disclaimer

This is a research subscription. Not a registered investment advisor. Not financial advice. Past paper-traded performance does not predict future results. The agent makes mistakes — see the 2022 retrospective for one trade entry that hit a −4.4% stop next day. You make your own trades. If you don't understand the risks of trading equities, please don't.

---

## What's next

I'm shipping this in increments:

1. **This week:** Free Substack. Read this, see if the framing resonates.
2. **Next 2 weeks:** Email signup for the weekly playbook + daily scan digest.
3. **Month 2-3:** Paid tier with the full pipeline (alerts, dashboard, custom watchlist).

If you have a 401k, a brokerage account, or any equity exposure and you want a defensive overlay built by a system that won't tilt, I'd love your eyes on it.

— *Subscribe below for the weekly playbook delivered to your inbox.*

[Subscribe →]
