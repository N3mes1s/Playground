"""Dependency-free charts: an ASCII plot for the terminal and a self-contained
SVG file for the artifacts directory. No matplotlib required."""

from __future__ import annotations

from typing import Sequence


def ascii_curve(treatment: Sequence[float], control: Sequence[float],
                height: int = 12, width: int | None = None) -> str:
    rounds = len(treatment)
    width = width or rounds
    lines = []
    lines.append("reward  1.0 |")
    for row in range(height, -1, -1):
        level = row / height
        label = f"{level:0.2f}" if row in (0, height // 2, height) else "    "
        cells = []
        for i in range(rounds):
            t = treatment[i]
            c = control[i]
            ch = " "
            if abs(c - level) <= 0.5 / height:
                ch = "o"          # control
            if abs(t - level) <= 0.5 / height:
                ch = "#"          # treatment (drawn on top)
            cells.append(ch)
        bar = "|" if row else "+"
        lines.append(f"      {label} {bar}" + "".join(cells))
    lines.append("           +" + "-" * rounds)
    lines.append("            round 1" + " " * max(0, rounds - 14) + f"round {rounds}")
    lines.append("")
    lines.append("      # = with continual learning      o = control (learning off)")
    return "\n".join(lines)


def svg_bars(labels: Sequence[str], values: Sequence[float], path: str,
             title: str, colors: Sequence[str] | None = None) -> None:
    W, H = 640, 380
    pad_l, pad_b, pad_t = 60, 60, 60
    plot_h = H - pad_t - pad_b
    n = len(values)
    slot = (W - pad_l - 30) / n
    bw = slot * 0.55
    colors = colors or ["#dc2626", "#2563eb", "#7c3aed", "#059669"]
    bars = []
    for i, (lab, v) in enumerate(zip(labels, values)):
        x = pad_l + i * slot + (slot - bw) / 2
        h = plot_h * v
        y = pad_t + plot_h - h
        c = colors[i % len(colors)]
        bars.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bw:.1f}" height="{h:.1f}" rx="4" fill="{c}"/>'
            f'<text x="{x+bw/2:.1f}" y="{y-8:.1f}" font-size="15" font-weight="600" '
            f'text-anchor="middle" fill="#111827">{v:.2f}</text>'
            f'<text x="{x+bw/2:.1f}" y="{H-pad_b+22:.1f}" font-size="13" '
            f'text-anchor="middle" fill="#374151">{lab}</text>'
        )
    grid = []
    for g in range(0, 6):
        v = g / 5
        yy = pad_t + plot_h * (1 - v)
        grid.append(f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{W-30}" y2="{yy:.1f}" '
                    f'stroke="#e5e7eb"/><text x="{pad_l-10}" y="{yy+4:.1f}" '
                    f'font-size="11" text-anchor="end" fill="#6b7280">{v:.1f}</text>')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="ui-sans-serif, system-ui, sans-serif">
  <rect width="{W}" height="{H}" fill="white"/>
  <text x="{W/2}" y="30" font-size="17" font-weight="600" text-anchor="middle" fill="#111827">{title}</text>
  {''.join(grid)}
  {''.join(bars)}
</svg>'''
    with open(path, "w") as f:
        f.write(svg)


def svg_curve(treatment: Sequence[float], control: Sequence[float],
              path: str, title: str = "Continual learning: reward per round") -> None:
    W, H = 720, 420
    pad_l, pad_r, pad_t, pad_b = 70, 30, 50, 60
    plot_w = W - pad_l - pad_r
    plot_h = H - pad_t - pad_b
    n = len(treatment)

    def x(i: int) -> float:
        return pad_l + (plot_w * (i / max(1, n - 1)))

    def y(v: float) -> float:
        return pad_t + plot_h * (1 - v)

    def poly(series: Sequence[float]) -> str:
        return " ".join(f"{x(i):.1f},{y(v):.1f}" for i, v in enumerate(series))

    grid = []
    for g in range(0, 6):
        v = g / 5
        yy = y(v)
        grid.append(
            f'<line x1="{pad_l}" y1="{yy:.1f}" x2="{W-pad_r}" y2="{yy:.1f}" '
            f'stroke="#e5e7eb" stroke-width="1"/>'
            f'<text x="{pad_l-10}" y="{yy+4:.1f}" font-size="12" '
            f'text-anchor="end" fill="#6b7280">{v:.1f}</text>'
        )
    grid_svg = "\n".join(grid)

    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" font-family="ui-sans-serif, system-ui, sans-serif">
  <rect width="{W}" height="{H}" fill="white"/>
  <text x="{W/2}" y="26" font-size="18" font-weight="600" text-anchor="middle" fill="#111827">{title}</text>
  {grid_svg}
  <line x1="{pad_l}" y1="{pad_t}" x2="{pad_l}" y2="{H-pad_b}" stroke="#9ca3af"/>
  <line x1="{pad_l}" y1="{H-pad_b}" x2="{W-pad_r}" y2="{H-pad_b}" stroke="#9ca3af"/>
  <text x="20" y="{pad_t+plot_h/2}" font-size="13" fill="#374151" transform="rotate(-90 20 {pad_t+plot_h/2})" text-anchor="middle">mean reward</text>
  <text x="{pad_l+plot_w/2}" y="{H-18}" font-size="13" fill="#374151" text-anchor="middle">round</text>
  <polyline fill="none" stroke="#2563eb" stroke-width="2.5" points="{poly(treatment)}"/>
  <polyline fill="none" stroke="#dc2626" stroke-width="2.5" stroke-dasharray="6 4" points="{poly(control)}"/>
  <g font-size="13">
    <rect x="{W-pad_r-230}" y="{pad_t}" width="14" height="3" fill="#2563eb"/>
    <text x="{W-pad_r-210}" y="{pad_t+5}" fill="#111827">with continual learning</text>
    <rect x="{W-pad_r-230}" y="{pad_t+22}" width="14" height="3" fill="#dc2626"/>
    <text x="{W-pad_r-210}" y="{pad_t+27}" fill="#111827">control (learning off)</text>
  </g>
</svg>'''
    with open(path, "w") as f:
        f.write(svg)
