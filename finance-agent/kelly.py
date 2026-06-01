"""Kelly-fraction position sizing — replaces fixed-% rules with edge-aware sizing.

Background:
* Kelly (1956): optimal bet fraction = (edge) / (variance), maximizes log-growth.
* Thorp's extension: practical fractional Kelly (typically 1/4 to 1/2) to
  trade some growth for lower variance and tail risk.
* Spitznagel "Safe Haven" (2021): the right portfolio is not the one with the
  highest mean — it's the one with the highest geometric (compounded) return
  given the agent's edge and downside.

The pure Kelly formula for a binary outcome:
    f* = (p*b - q) / b
where p = win prob, b = win/loss ratio, q = 1-p.

For continuous returns it generalizes to:
    f* ≈ μ / σ²
where μ is expected excess return, σ² is variance of return.

We use fractional Kelly (default 0.25) and CAP against the hard rails. The
Risk Manager calls `kelly_size(...)` to convert a Trader proposal into a
final position size.
"""
from dataclasses import dataclass

import config


@dataclass
class EdgeEstimate:
    """An estimate of a trade's edge for Kelly sizing."""
    win_prob: float            # 0-1
    avg_win_return: float      # e.g. 0.08 for +8%
    avg_loss_return: float     # negative, e.g. -0.04 for -4% stop
    confidence: int = 3        # 1-5, scales fractional-Kelly multiplier


def kelly_fraction(edge: EdgeEstimate, fractional: float = 0.25) -> float:
    """Return the Kelly-optimal fraction of NAV to allocate."""
    p = max(0.0, min(1.0, edge.win_prob))
    q = 1.0 - p
    win = abs(edge.avg_win_return)
    loss = abs(edge.avg_loss_return)
    if win <= 0 or loss <= 0:
        return 0.0
    b = win / loss
    f_star = (p * b - q) / b
    if f_star <= 0:
        return 0.0
    # Confidence-scaled fractional Kelly: 1-5 maps to 0.1-0.5x
    conf_mult = 0.1 + (edge.confidence - 1) * 0.1
    return f_star * fractional * conf_mult / 0.25


def kelly_position_size(
    nav: float,
    edge: EdgeEstimate,
    price: float,
    current_position_value: float = 0.0,
    fractional: float = 0.25,
) -> dict:
    """Compute Kelly-recommended notional + share count for a trade.

    Returns a dict with the suggested size, the Kelly fraction, and whether
    rails would clamp it.
    """
    f = kelly_fraction(edge, fractional)
    notional = f * nav
    # Hard rail: max position 20% of NAV, max order 10%
    cap_position = nav * config.MAX_POSITION_PCT - current_position_value
    cap_order = nav * config.MAX_ORDER_PCT
    rails_clamp = min(cap_position, cap_order)
    clamped = max(0.0, min(notional, rails_clamp))
    shares = clamped / price if price > 0 else 0
    return {
        "kelly_fraction": round(f, 4),
        "raw_notional": round(notional, 2),
        "clamped_notional": round(clamped, 2),
        "shares": round(shares, 4),
        "was_clamped": clamped < notional,
        "reasoning": (
            f"edge p={edge.win_prob:.2f}, win={edge.avg_win_return:+.2%}, "
            f"loss={edge.avg_loss_return:+.2%}, conf={edge.confidence}/5 → "
            f"kelly {f:.2%} of ${nav:,.0f} = ${notional:.0f} "
            f"({'rail-clamped to' if clamped < notional else 'within rails:'} ${clamped:.0f})"
        ),
    }
