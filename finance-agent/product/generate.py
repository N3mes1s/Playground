"""Render product HTML pages by injecting real backtest data into templates."""
import json
from datetime import date
from pathlib import Path

ROOT = Path(__file__).parent
DATA = ROOT.parent / "data"
OUT = ROOT


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
        kind_color = {"fill": "text-emerald-400", "order_open": "text-blue-400", "order_cancel": "text-zinc-500", "note": "text-zinc-300"}.get(kind, "text-zinc-300")
        journal_html += f"""
        <div class="border-l-2 border-zinc-800 pl-3 py-1.5">
          <div class="flex items-center gap-2 text-xs">
            <span class="font-mono text-zinc-500">{entry.get('t', '')[:10]}</span>
            <span class="{kind_color} font-medium uppercase tracking-wide">{kind}</span>
          </div>
          <div class="text-sm text-zinc-200 mt-0.5">{text[:380]}</div>
        </div>"""

    playbook_excerpt = playbook[:4500] if playbook else "(playbook not yet generated)"

    weekly_summary = last_week.get("summary", "")
    weekly_pct = fmt_pct(last_week["weekly_return"])
    weekly_dollar = fmt_money(last_week["end_value"] - last_week["start_value"])
    weekly_value = fmt_money(last_week["end_value"])
    weekly_color = "text-emerald-400" if last_week["weekly_return"] > 0 else ("text-red-400" if last_week["weekly_return"] < 0 else "text-zinc-400")

    template = (ROOT / "app.template.html").read_text()
    return (template
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
