from dataclasses import dataclass

import config
import portfolio as pf


@dataclass
class RiskCheck:
    ok: bool
    reason: str = ""


def evaluate_buy(
    state: pf.State,
    symbol: str,
    qty: float,
    price: float,
    quotes: dict[str, float],
) -> RiskCheck:
    notional = qty * price
    portfolio_value = pf.market_value(state, quotes)

    if state.halted_until:
        return RiskCheck(False, f"trading halted until {state.halted_until}")

    if notional > portfolio_value * config.MAX_ORDER_PCT:
        return RiskCheck(
            False,
            f"order notional ${notional:.2f} exceeds per-trade cap "
            f"({config.MAX_ORDER_PCT:.0%} of ${portfolio_value:.2f})",
        )

    if state.cash - notional < portfolio_value * config.MIN_CASH_PCT:
        return RiskCheck(False, f"would breach min cash reserve {config.MIN_CASH_PCT:.0%}")

    existing = state.positions.get(symbol)
    new_qty = (existing.qty if existing else 0) + qty
    new_exposure = new_qty * price
    if new_exposure > portfolio_value * config.MAX_POSITION_PCT:
        return RiskCheck(
            False,
            f"position would be {new_exposure / portfolio_value:.1%} of port, "
            f"max {config.MAX_POSITION_PCT:.0%}",
        )

    if not existing and len(state.positions) >= config.MAX_POSITIONS:
        return RiskCheck(False, f"already at max {config.MAX_POSITIONS} positions")

    return RiskCheck(True)


def evaluate_sell(state: pf.State, symbol: str, qty: float) -> RiskCheck:
    if state.halted_until:
        return RiskCheck(False, f"trading halted until {state.halted_until}")
    pos = state.positions.get(symbol)
    if not pos:
        return RiskCheck(False, f"no open position in {symbol}")
    if qty > pos.qty + 1e-9:
        return RiskCheck(False, f"sell qty {qty} exceeds holding {pos.qty}")
    return RiskCheck(True)


def check_daily_halt(state: pf.State, quotes: dict[str, float]) -> bool:
    if state.day_start_value <= 0:
        return False
    current = pf.market_value(state, quotes)
    loss = (state.day_start_value - current) / state.day_start_value
    if loss >= config.DAILY_LOSS_HALT_PCT:
        state.halted_until = state.day_start_date + "T23:59:59Z"
        pf.save(state)
        return True
    return False


def summary(state: pf.State, quotes: dict[str, float]) -> dict:
    portfolio_value = pf.market_value(state, quotes)
    intraday = 0.0
    if state.day_start_value > 0:
        intraday = (portfolio_value - state.day_start_value) / state.day_start_value
    weekly = 0.0
    if state.starting_cash > 0:
        weekly = (portfolio_value - state.starting_cash) / state.starting_cash
    return {
        "portfolio_value": round(portfolio_value, 2),
        "cash": round(state.cash, 2),
        "cash_pct": round(state.cash / portfolio_value, 4) if portfolio_value else 1.0,
        "positions_count": len(state.positions),
        "intraday_pnl_pct": round(intraday, 4),
        "lifetime_pnl_pct": round(weekly, 4),
        "halted": bool(state.halted_until),
        "max_position_pct": config.MAX_POSITION_PCT,
        "max_order_pct": config.MAX_ORDER_PCT,
        "min_cash_pct": config.MIN_CASH_PCT,
        "daily_halt_pct": config.DAILY_LOSS_HALT_PCT,
    }
