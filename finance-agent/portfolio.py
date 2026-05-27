import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import clock
import config


@dataclass
class Position:
    symbol: str
    qty: float
    avg_cost: float


@dataclass
class Fill:
    id: str
    symbol: str
    side: str
    qty: float
    price: float
    timestamp: str
    order_id: str


@dataclass
class Order:
    id: str
    symbol: str
    side: str
    qty: float
    order_type: str
    limit_price: Optional[float]
    status: str
    created_at: str
    filled_at: Optional[str] = None
    fill_price: Optional[float] = None
    reason: Optional[str] = None


@dataclass
class State:
    starting_cash: float
    cash: float
    watchlist: list[str]
    positions: dict[str, Position] = field(default_factory=dict)
    open_orders: list[Order] = field(default_factory=list)
    fills: list[Fill] = field(default_factory=list)
    day_start_value: float = 0.0
    day_start_date: str = ""
    halted_until: Optional[str] = None
    created_at: str = ""


def _now() -> str:
    return clock.iso()


def _today() -> str:
    return clock.today().isoformat()


def load() -> State:
    if not config.PORTFOLIO_PATH.exists():
        raise FileNotFoundError(
            f"No portfolio at {config.PORTFOLIO_PATH}. Run `python cli.py init` first."
        )
    raw = json.loads(config.PORTFOLIO_PATH.read_text())
    raw["positions"] = {k: Position(**v) for k, v in raw["positions"].items()}
    raw["open_orders"] = [Order(**o) for o in raw["open_orders"]]
    raw["fills"] = [Fill(**f) for f in raw["fills"]]
    return State(**raw)


def save(state: State) -> None:
    raw = asdict(state)
    config.PORTFOLIO_PATH.write_text(json.dumps(raw, indent=2, default=str))


def init(starting_cash: float, watchlist: list[str]) -> State:
    state = State(
        starting_cash=starting_cash,
        cash=starting_cash,
        watchlist=watchlist,
        day_start_value=starting_cash,
        day_start_date=_today(),
        created_at=_now(),
    )
    save(state)
    return state


def market_value(state: State, quotes: dict[str, float]) -> float:
    total = state.cash
    for pos in state.positions.values():
        price = quotes.get(pos.symbol, pos.avg_cost)
        total += pos.qty * price
    return total


def roll_day_if_needed(state: State, quotes: dict[str, float]) -> None:
    today = _today()
    if state.day_start_date != today:
        state.day_start_value = market_value(state, quotes)
        state.day_start_date = today
        state.halted_until = None
        save(state)


def apply_fill(state: State, order: Order, price: float) -> Fill:
    fill = Fill(
        id=f"fil_{uuid.uuid4().hex[:12]}",
        symbol=order.symbol,
        side=order.side,
        qty=order.qty,
        price=price,
        timestamp=_now(),
        order_id=order.id,
    )
    state.fills.append(fill)
    order.status = "filled"
    order.filled_at = fill.timestamp
    order.fill_price = price

    notional = order.qty * price
    if order.side == "buy":
        state.cash -= notional
        pos = state.positions.get(order.symbol)
        if pos:
            new_qty = pos.qty + order.qty
            pos.avg_cost = (pos.avg_cost * pos.qty + notional) / new_qty
            pos.qty = new_qty
        else:
            state.positions[order.symbol] = Position(
                symbol=order.symbol, qty=order.qty, avg_cost=price
            )
    else:
        state.cash += notional
        pos = state.positions[order.symbol]
        pos.qty -= order.qty
        if pos.qty <= 1e-9:
            del state.positions[order.symbol]

    return fill


def new_order(
    symbol: str,
    side: str,
    qty: float,
    order_type: str,
    limit_price: Optional[float],
    reason: Optional[str],
) -> Order:
    return Order(
        id=f"ord_{uuid.uuid4().hex[:12]}",
        symbol=symbol,
        side=side,
        qty=qty,
        order_type=order_type,
        limit_price=limit_price,
        status="open",
        created_at=_now(),
        reason=reason,
    )
