import argparse
import json
import os
import sys
import time
from datetime import date, datetime, timezone

import agent
import config
import market_data
import portfolio as pf
import risk


def cmd_whoami(_: argparse.Namespace) -> None:
    try:
        creds = config.resolve_anthropic_credentials()
        source = "ANTHROPIC_API_KEY env" if "api_key" in creds else (
            "ANTHROPIC_AUTH_TOKEN env" if os.getenv("ANTHROPIC_AUTH_TOKEN")
            else "Claude Code session ingress token"
        )
        anthropic_status = {"ok": True, "source": source, "model": config.MODEL}
    except RuntimeError as e:
        anthropic_status = {"ok": False, "error": str(e)}
    print(json.dumps({
        "anthropic": anthropic_status,
        "parallel_ai": {"ok": bool(config.PARALLEL_API_KEY)},
        "data_dir": str(config.DATA_DIR),
    }, indent=2))


def cmd_init(args: argparse.Namespace) -> None:
    if config.PORTFOLIO_PATH.exists() and not args.force:
        print(f"Portfolio exists at {config.PORTFOLIO_PATH}. Use --force to overwrite.")
        sys.exit(1)
    watchlist = [s.strip().upper() for s in args.watchlist.split(",") if s.strip()]
    state = pf.init(starting_cash=args.starting_cash, watchlist=watchlist)
    print(f"Initialized portfolio: ${state.starting_cash:.2f} cash, watchlist: {watchlist}")


def cmd_status(_: argparse.Namespace) -> None:
    state = pf.load()
    quotes = market_data.quotes(list(state.watchlist) + list(state.positions.keys()))
    pf.roll_day_if_needed(state, quotes)
    summary = risk.summary(state, quotes)
    print(json.dumps({
        "as_of": datetime.now(timezone.utc).isoformat(),
        "market_open": market_data.market_is_open(),
        "positions": [
            {
                "symbol": p.symbol,
                "qty": p.qty,
                "avg_cost": round(p.avg_cost, 4),
                "last": round(quotes.get(p.symbol, p.avg_cost), 4),
            }
            for p in state.positions.values()
        ],
        "open_orders": [o.id for o in state.open_orders],
        "risk": summary,
    }, indent=2))


def cmd_tick(args: argparse.Namespace) -> None:
    if args.multiagent:
        import multiagent
        result = multiagent.run_tick_multiagent(debate_rounds=args.debate_rounds)
    else:
        result = agent.run_tick()
    print(json.dumps(result, indent=2, default=str))


def cmd_loop(args: argparse.Namespace) -> None:
    interval = args.interval or config.TICK_INTERVAL
    print(f"Starting intraday loop — tick every {interval}s during market hours.")
    last_close_date = None
    while True:
        try:
            now = datetime.now(timezone.utc).astimezone(market_data.ET)
            if market_data.market_is_open(now.astimezone(timezone.utc)):
                result = agent.run_tick()
                print(f"[{result['t']}] tool_calls={result['tool_calls']} "
                      f"pv=${result['risk']['portfolio_value']:.2f} "
                      f"intraday={result['risk']['intraday_pnl_pct']:.2%}")
            else:
                if now.weekday() == 4 and now.hour >= 16 and last_close_date != now.date():
                    print(f"[{now.isoformat()}] Friday after close — running weekly close.")
                    close_result = agent.run_weekly_close()
                    print(close_result["summary"][:500])
                    last_close_date = now.date()
                next_open = market_data.next_open(now.astimezone(timezone.utc))
                wait = max(60, min(interval * 4, (next_open - now).total_seconds()))
                print(f"[{now.isoformat()}] Market closed. Next open ~{next_open.isoformat()}. "
                      f"Sleeping {int(wait)}s.")
                time.sleep(wait)
                continue
            time.sleep(interval)
        except KeyboardInterrupt:
            print("\nLoop interrupted by user.")
            return
        except Exception as e:
            print(f"[error] {e}; sleeping 60s before retry.")
            time.sleep(60)


def cmd_weekly_close(_: argparse.Namespace) -> None:
    result = agent.run_weekly_close()
    print(json.dumps(result, indent=2, default=str))


def cmd_monitors_setup(args: argparse.Namespace) -> None:
    import monitors
    out = monitors.setup_standard_monitors(dry_run=args.dry_run)
    print(json.dumps(out, indent=2))


def cmd_monitors_list(_: argparse.Namespace) -> None:
    import monitors
    remote = monitors.list_monitors_remote()
    local = monitors._load_registry()
    print(json.dumps({"remote_count": len(remote), "local_registry": local,
                      "remote": [{"id": m.get("monitor_id") or m.get("id"),
                                  "name": (m.get("metadata") or {}).get("name"),
                                  "query": (m.get("settings") or {}).get("query", "")[:120],
                                  "frequency": m.get("frequency"),
                                  "status": m.get("status")}
                                 for m in remote]}, indent=2))


def cmd_monitors_poll(_: argparse.Namespace) -> None:
    import monitors
    events = monitors.poll_all_recent(max_events_per_monitor=10)
    total = sum(len(v) if isinstance(v, list) else 0 for v in events.values())
    print(f"Polled {len(events)} monitors, {total} events total\n")
    for name, evs in events.items():
        non_completion = [e for e in evs if isinstance(e, dict) and e.get("event_type") != "completion"]
        print(f"  {name}: {len(evs)} events ({len(non_completion)} non-completion)")
    print()
    print(json.dumps(events, indent=2, default=str)[:8000])


def cmd_monitors_delete(args: argparse.Namespace) -> None:
    import monitors
    for name in args.names:
        reg = monitors._load_registry()
        if name not in reg:
            print(f"{name}: not in registry")
            continue
        mid = reg[name]["monitor_id"]
        code = monitors.delete_monitor(mid)
        if code in (200, 204):
            del reg[name]
            monitors._save_registry(reg)
            print(f"{name}: deleted ({mid})")
        else:
            print(f"{name}: delete returned {code}")


def cmd_index_news(args: argparse.Namespace) -> None:
    import news_index
    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end)
    watchlist = [s.strip().upper() for s in args.watchlist.split(",") if s.strip()]
    stats = news_index.build_range(start, end, watchlist, force=args.force)
    print(json.dumps(stats, indent=2))


def cmd_backtest(args: argparse.Namespace) -> None:
    import backtest
    start = date.fromisoformat(args.start)
    end = date.fromisoformat(args.end)
    watchlist = [s.strip().upper() for s in args.watchlist.split(",") if s.strip()]
    summary = backtest.run(
        start=start,
        end=end,
        starting_cash=args.starting_cash,
        watchlist=watchlist,
        run_id=args.run_id,
        use_multiagent=args.multiagent,
    )
    print("\n" + "=" * 60)
    print("BACKTEST SUMMARY")
    print("=" * 60)
    print(json.dumps(summary, indent=2, default=str))


def cmd_reset(args: argparse.Namespace) -> None:
    for path in [config.PORTFOLIO_PATH, config.JOURNAL_PATH, config.TICK_LOG_PATH]:
        if path.exists():
            path.unlink()
    if args.with_playbook and config.PLAYBOOK_PATH.exists():
        config.PLAYBOOK_PATH.unlink()
    print("Reset complete.")


def main() -> None:
    parser = argparse.ArgumentParser(prog="finance-agent")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_who = sub.add_parser("whoami", help="Show which Anthropic credential is in use.")
    p_who.set_defaults(func=cmd_whoami)

    p_init = sub.add_parser("init", help="Create a new paper portfolio.")
    p_init.add_argument("--starting-cash", type=float, default=10000)
    p_init.add_argument("--watchlist", type=str, default="SPY,QQQ,AAPL,MSFT,NVDA")
    p_init.add_argument("--force", action="store_true")
    p_init.set_defaults(func=cmd_init)

    p_status = sub.add_parser("status", help="Print current portfolio state.")
    p_status.set_defaults(func=cmd_status)

    p_tick = sub.add_parser("tick", help="Run one agent tick.")
    p_tick.add_argument("--multiagent", action="store_true",
                        help="Use the TradingAgents-style multi-agent debate pipeline.")
    p_tick.add_argument("--debate-rounds", type=int, default=1,
                        help="Number of bull/bear debate cycles (multiagent only).")
    p_tick.set_defaults(func=cmd_tick)

    p_loop = sub.add_parser("loop", help="Run the intraday loop.")
    p_loop.add_argument("--interval", type=int, default=None,
                        help=f"Seconds between ticks (default {config.TICK_INTERVAL}).")
    p_loop.set_defaults(func=cmd_loop)

    p_close = sub.add_parser("weekly-close", help="Run the weekly retrospective + playbook rewrite.")
    p_close.set_defaults(func=cmd_weekly_close)

    p_msetup = sub.add_parser("monitors-setup",
                              help="Create the standard set of parallel.ai monitors.")
    p_msetup.add_argument("--dry-run", action="store_true")
    p_msetup.set_defaults(func=cmd_monitors_setup)

    p_mlist = sub.add_parser("monitors-list", help="List active monitors (remote + local registry).")
    p_mlist.set_defaults(func=cmd_monitors_list)

    p_mpoll = sub.add_parser("monitors-poll", help="Poll all monitors for recent events.")
    p_mpoll.set_defaults(func=cmd_monitors_poll)

    p_mdel = sub.add_parser("monitors-delete", help="Delete monitor(s) by registry name.")
    p_mdel.add_argument("names", nargs="+")
    p_mdel.set_defaults(func=cmd_monitors_delete)

    p_idx = sub.add_parser("index-news",
                           help="Pre-fetch historical news from parallel.ai for backtest dates.")
    p_idx.add_argument("--start", type=str, required=True, help="YYYY-MM-DD")
    p_idx.add_argument("--end", type=str, required=True, help="YYYY-MM-DD")
    p_idx.add_argument("--watchlist", type=str,
                       default="SPY,QQQ,AAPL,MSFT,NVDA,GOOGL,META,AMZN,TSLA,AMD")
    p_idx.add_argument("--force", action="store_true",
                       help="Re-fetch even if cache exists.")
    p_idx.set_defaults(func=cmd_index_news)

    p_bt = sub.add_parser("backtest", help="Run a historical backtest.")
    p_bt.add_argument("--start", type=str, required=True, help="YYYY-MM-DD")
    p_bt.add_argument("--end", type=str, required=True, help="YYYY-MM-DD")
    p_bt.add_argument("--starting-cash", type=float, default=10000)
    p_bt.add_argument("--watchlist", type=str,
                      default="SPY,QQQ,AAPL,MSFT,NVDA,GOOGL,META,AMZN,TSLA,AMD")
    p_bt.add_argument("--run-id", type=str, default=None)
    p_bt.add_argument("--multiagent", action="store_true",
                      help="Use the TradingAgents-style multi-agent pipeline (4-5x cost).")
    p_bt.set_defaults(func=cmd_backtest)

    p_reset = sub.add_parser("reset", help="Wipe portfolio, journal, tick log.")
    p_reset.add_argument("--with-playbook", action="store_true",
                         help="Also delete the playbook.")
    p_reset.set_defaults(func=cmd_reset)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
