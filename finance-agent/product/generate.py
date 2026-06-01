"""Render product HTML pages by injecting real data into templates."""
import json
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT.parent / "data"
OUT = ROOT

# Allow importing finance-agent modules so we can pull LIVE data sources
sys.path.insert(0, str(ROOT.parent))


def load_backtest(run_id: str) -> dict:
    with open(DATA / "backtests" / run_id / "summary.json") as f:
        return json.load(f)


def load_playbook(run_id: str) -> str:
    p = DATA / "backtests" / run_id / "playbook.md"
    return p.read_text() if p.exists() else ""


def load_journal(run_id: str, last_n: int = 20) -> list[dict]:
    p = DATA / "backtests" / run_id / "journal.jsonl"
    if not p.exists():
        return []
    lines = [json.loads(l) for l in p.read_text().splitlines() if l.strip()]
    return lines[-last_n:]


def load_news_for_date(d: str) -> dict | None:
    p = DATA / "news_cache" / f"{d}.json"
    if not p.exists():
        return None
    return json.loads(p.read_text())


def fmt_pct(x: float) -> str:
    return f"{x*100:+.2f}%"


def fmt_money(x: float) -> str:
    return f"${x:,.2f}"


def render_landing() -> str:
    bull_blind = load_backtest("3mo_q1q2")
    bull_news = load_backtest("3mo_q1q2_with_news")
    bear = load_backtest("3mo_bear_2022")

    bull_weeks_json = json.dumps([{"d": w["week_end"], "r": w["weekly_return"], "v": w["end_value"]} for w in bull_news["weekly_marks"]])
    bear_weeks_json = json.dumps([{"d": w["week_end"], "r": w["weekly_return"], "v": w["end_value"]} for w in bear["weekly_marks"]])

    template = (ROOT / "landing.template.html").read_text()
    return (template
            .replace("{{BULL_RETURN}}", fmt_pct(bull_news["total_return"]))
            .replace("{{BEAR_RETURN}}", fmt_pct(bear["total_return"]))
            .replace("{{SPY_BULL}}", "+8.89%")
            .replace("{{SPY_BEAR}}", "−7.69%")
            .replace("{{BULL_BEST}}", fmt_pct(bull_news["best_week"]["weekly_return"]))
            .replace("{{BULL_WORST}}", fmt_pct(bull_news["worst_week"]["weekly_return"]))
            .replace("{{BEAR_WORST}}", fmt_pct(bear["worst_week"]["weekly_return"]))
            .replace("{{BULL_WEEKS_JSON}}", bull_weeks_json)
            .replace("{{BEAR_WEEKS_JSON}}", bear_weeks_json))


def fetch_live_kalshi() -> list[dict]:
    """Pull current Kalshi prediction-market probabilities."""
    try:
        import prediction_markets as pmkt
        markets = pmkt.get_economic_priors(category="fed_rates")
        rates = [m for m in markets if "FEDHIKE" in (m.get("ticker") or "") and "26" in (m.get("ticker") or "") or "27" in (m.get("ticker") or "")][:4]
        if not rates:
            rates = markets[:4]
        cpi_markets = pmkt.get_economic_priors(category="cpi")[:3]
        return [{"label": m.get("question", "")[:60], "prob": m.get("implied_yes_prob"),
                 "ticker": m.get("ticker"), "vol24h": m.get("volume_24h")}
                for m in (rates + cpi_markets) if m.get("implied_yes_prob") is not None][:6]
    except Exception as e:
        return [{"label": f"(kalshi fetch failed: {e})", "prob": None}]


def fetch_live_flow() -> list[dict]:
    """Pull current unusual options flow across the demo watchlist."""
    try:
        import options_flow as ofl
        result = ofl.watchlist_flow_scan(
            ["NVDA", "TSLA", "AMD", "AAPL", "META"],
            min_volume=2000, min_notional=500_000, min_vol_oi_ratio=1.5,
        )
        return result.get("unusual_contracts", [])[:6]
    except Exception as e:
        return []


def fetch_live_monitor_events() -> list[dict]:
    """Poll recently-detected monitor events."""
    try:
        import monitors
        events_by_monitor = monitors.poll_all_recent(max_events_per_monitor=3)
        flattened = []
        for monitor_name, events in events_by_monitor.items():
            if not isinstance(events, list):
                continue
            for e in events:
                if not isinstance(e, dict) or e.get("event_type") == "completion":
                    continue
                flattened.append({"monitor": monitor_name, **e})
        flattened.sort(key=lambda e: e.get("timestamp", ""), reverse=True)
        return flattened[:6]
    except Exception as e:
        return []


def render_app() -> str:
    bull_news = load_backtest("3mo_q1q2_with_news")
    playbook = load_playbook("3mo_q1q2_with_news")
    journal = load_journal("3mo_q1q2_with_news", last_n=15)

    last_week = bull_news["weekly_marks"][-2]
    weeks_json = json.dumps([{"d": w["week_end"], "r": w["weekly_return"], "v": w["end_value"]} for w in bull_news["weekly_marks"]])

    journal_html = ""
    for entry in reversed(journal[-12:]):
        kind = entry.get("kind", "note")
        text = entry.get("note") or entry.get("summary") or ""
        if not text and entry.get("order"):
            o = entry["order"]
            text = f"{o.get('side', '?').upper()} {o.get('qty', '?')} {o.get('symbol', '?')} @ {o.get('order_type', '?')} — {o.get('reason') or 'no reason'}"
        kind_styles = {
            "fill": ("#10b981", "rgba(16,185,129,0.08)"),
            "order_open": ("#60a5fa", "rgba(96,165,250,0.08)"),
            "order_cancel": ("#a3a3a3", "rgba(163,163,163,0.06)"),
            "note": ("#fbbf24", "rgba(251,191,36,0.06)"),
        }
        kind_color, kind_bg = kind_styles.get(kind, ("#a3a3a3", "rgba(163,163,163,0.06)"))
        journal_html += f"""
        <div class="py-2.5 pl-4 border-l-2 mb-1" style="border-color: {kind_color};">
          <div class="flex items-center gap-2 text-[10px] mono mb-1">
            <span class="text-zinc-500">{entry.get('t', '')[:10]}</span>
            <span class="font-bold uppercase tracking-[0.1em] px-1.5 py-0.5 rounded" style="background: {kind_bg}; color: {kind_color};">{kind}</span>
          </div>
          <div class="text-[13px] text-zinc-300 leading-relaxed">{text[:380]}</div>
        </div>"""

    playbook_excerpt = playbook[:4500] if playbook else "(playbook not yet generated)"

    # Live data panels
    kalshi_panels = fetch_live_kalshi()
    flow_panels = fetch_live_flow()

    kalshi_html = ""
    for m in kalshi_panels[:5]:
        p = m.get("prob")
        prob_pct = f"{p*100:.0f}%" if isinstance(p, (int, float)) else "—"
        # Color the probability bar
        if isinstance(p, (int, float)):
            bar_pct = max(1, int(p * 100))
            prob_color = "#10b981" if p > 0.5 else ("#f43f5e" if p < 0.3 else "#a3a3a3")
        else:
            bar_pct = 0
            prob_color = "#525252"
        kalshi_html += f"""
        <div class="py-3 border-b" style="border-color: var(--border);">
          <div class="flex items-center justify-between mb-2">
            <div class="text-sm text-zinc-200 leading-tight pr-3 flex-1">{m.get('label','')}</div>
            <div class="num-display text-xl font-bold mono" style="color: {prob_color};">{prob_pct}</div>
          </div>
          <div class="flex items-center justify-between gap-3">
            <div class="flex-1 h-1 rounded-full" style="background: var(--surface-2);">
              <div class="h-1 rounded-full" style="width: {bar_pct}%; background: {prob_color}; opacity: 0.6;"></div>
            </div>
            <div class="text-xs text-zinc-600 mono">{m.get('ticker','')}</div>
          </div>
        </div>"""
    if not kalshi_html:
        kalshi_html = '<div class="text-xs text-zinc-500 mono py-6 text-center">No active markets matched.</div>'

    flow_html = ""
    for h in flow_panels[:5]:
        side_color = "#10b981" if h.get("side") == "call" else "#f43f5e"
        side_bg = "rgba(16,185,129,0.08)" if h.get("side") == "call" else "rgba(244,63,94,0.08)"
        notional = h.get("notional_usd", 0)
        flow_html += f"""
        <div class="py-3.5 border-b" style="border-color: var(--border);">
          <div class="flex items-center justify-between mb-1.5">
            <div class="flex items-center gap-2.5">
              <span class="font-bold text-base">{h.get('symbol','')}</span>
              <span class="px-1.5 py-0.5 rounded text-[10px] mono uppercase font-semibold tracking-wider" style="background: {side_bg}; color: {side_color};">{h.get('side','')}</span>
              <span class="text-sm text-zinc-300 mono">${h.get('strike','')}</span>
              <span class="text-xs text-zinc-500 mono">{h.get('dte','')}d</span>
            </div>
            <div class="num-display font-bold mono" style="color: {side_color};">${notional:,.0f}</div>
          </div>
          <div class="text-xs text-zinc-600 mono">vol {h.get('volume',0):,} · OI {h.get('open_interest',0):,} · vol/OI {h.get('vol_oi_ratio','—')}</div>
        </div>"""
    if not flow_html:
        flow_html = '<div class="text-xs text-zinc-500 mono py-6 text-center">No unusual flow this scan.</div>'


    weekly_summary = last_week.get("summary", "")
    weekly_pct = fmt_pct(last_week["weekly_return"])
    weekly_dollar = fmt_money(last_week["end_value"] - last_week["start_value"])
    weekly_value = fmt_money(last_week["end_value"])
    weekly_color = "text-emerald-400" if last_week["weekly_return"] > 0 else ("text-red-400" if last_week["weekly_return"] < 0 else "text-zinc-400")

    template = (ROOT / "app.template.html").read_text()
    return (template
            .replace("{{KALSHI_PANELS}}", kalshi_html)
            .replace("{{FLOW_PANELS}}", flow_html)
            .replace("{{WEEK_END_DATE}}", last_week["week_end"])
            .replace("{{TOTAL_VALUE}}", fmt_money(bull_news["final_value"]))
            .replace("{{TOTAL_RETURN}}", fmt_pct(bull_news["total_return"]))
            .replace("{{TOTAL_RETURN_COLOR}}", "text-emerald-400" if bull_news["total_return"] > 0 else "text-red-400")
            .replace("{{LAST_WEEK_PCT}}", weekly_pct)
            .replace("{{LAST_WEEK_DOLLAR}}", weekly_dollar)
            .replace("{{LAST_WEEK_VALUE}}", weekly_value)
            .replace("{{LAST_WEEK_COLOR}}", weekly_color)
            .replace("{{LAST_WEEK_SUMMARY}}", weekly_summary)
            .replace("{{JOURNAL_ENTRIES}}", journal_html)
            .replace("{{PLAYBOOK_EXCERPT}}", playbook_excerpt)
            .replace("{{WEEKS_JSON}}", weeks_json)
            .replace("{{GREEN_WEEKS}}", str(bull_news["green_weeks"]))
            .replace("{{RED_WEEKS}}", str(bull_news["red_weeks"]))
            .replace("{{FLAT_WEEKS}}", str(bull_news["flat_weeks"])))


def render_email_weekly() -> str:
    bull_news = load_backtest("3mo_q1q2_with_news")
    last_week = bull_news["weekly_marks"][-2]
    template = (ROOT / "email_weekly.template.html").read_text()
    return (template
            .replace("{{WEEK_START}}", last_week["week_start"])
            .replace("{{WEEK_END}}", last_week["week_end"])
            .replace("{{P_AND_L}}", fmt_money(last_week["end_value"] - last_week["start_value"]))
            .replace("{{P_AND_L_PCT}}", fmt_pct(last_week["weekly_return"]))
            .replace("{{TOTAL_VALUE}}", fmt_money(last_week["end_value"]))
            .replace("{{COLOR}}", "#10b981" if last_week["weekly_return"] >= 0 else "#ef4444")
            .replace("{{TAG}}", "GREEN" if last_week["weekly_return"] > 0 else ("RED" if last_week["weekly_return"] < 0 else "FLAT"))
            .replace("{{SUMMARY}}", last_week.get("summary", "").replace("\n", "<br>")))


def main():
    (OUT / "landing.html").write_text(render_landing())
    print(f"wrote {OUT / 'landing.html'}")
    (OUT / "app.html").write_text(render_app())
    print(f"wrote {OUT / 'app.html'}")
    (OUT / "email_weekly.html").write_text(render_email_weekly())
    print(f"wrote {OUT / 'email_weekly.html'}")


if __name__ == "__main__":
    main()
