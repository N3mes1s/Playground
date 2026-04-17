"""
Render a token visualization as a self-contained interactive HTML file.

Multi-panel layout:
1. Summary stats bar
2. Timeline waterfall (main view) — each turn is a row, segments = thinking/tools/text
3. Aggregate donut — total token breakdown by category
4. Context growth chart — input tokens + cache ratio per turn
5. Top tools table — ranked by token consumption
"""

import json
import html as html_mod
from flamegraph import SessionViz, viz_to_json, session_to_viz
from parser import Session


CATEGORY_COLORS = {
    "thinking": "#e8524a",
    "text":     "#4a90d9",
    "read":     "#50b86c",
    "write":    "#f5a623",
    "bash":     "#9b59b6",
    "search":   "#2ecc71",
    "agent":    "#e74c3c",
    "other":    "#3498db",
    "cache":    "#555555",
    "fresh":    "#888888",
}


def render_html(session: Session, title: str = "Token Flamegraph") -> str:
    viz = session_to_viz(session)
    data = viz_to_json(viz)
    data_json = json.dumps(data)
    colors_json = json.dumps(CATEGORY_COLORS)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html_mod.escape(title)}</title>
<style>
:root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128;
    --border: #30363d; --text: #c9d1d9; --text2: #8b949e;
    --text-bright: #f0f6fc; --accent: #58a6ff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: var(--bg); color: var(--text); }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
h1 {{ font-size: 20px; color: var(--text-bright); margin-bottom: 4px; }}
.subtitle {{ font-size: 13px; color: var(--text2); margin-bottom: 16px; }}

/* Stats bar */
.stats {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
.stat {{ background: var(--bg2); padding: 10px 16px; border-radius: 8px; border: 1px solid var(--border); min-width: 120px; }}
.stat-label {{ color: var(--text2); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
.stat-value {{ color: var(--text-bright); font-size: 20px; font-weight: 700; margin-top: 2px; }}
.stat-sub {{ color: var(--text2); font-size: 11px; }}

/* Panels */
.panels {{ display: grid; grid-template-columns: 1fr 340px; gap: 16px; margin-bottom: 20px; }}
.panel {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.panel-title {{ font-size: 13px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; font-weight: 600; }}
.panel-full {{ grid-column: 1 / -1; }}

/* Waterfall */
.waterfall {{ overflow-x: auto; }}
.wf-row {{ display: flex; align-items: center; margin-bottom: 3px; min-height: 28px; }}
.wf-label {{ width: 80px; flex-shrink: 0; font-size: 12px; color: var(--text2); text-align: right; padding-right: 10px; }}
.wf-bar-container {{ flex: 1; position: relative; height: 26px; }}
.wf-segment {{
    position: absolute; height: 26px; border-radius: 3px;
    cursor: pointer; transition: opacity 0.1s, transform 0.1s;
    display: flex; align-items: center; padding: 0 4px;
    font-size: 10px; color: #fff; overflow: hidden; white-space: nowrap;
    text-shadow: 0 1px 2px rgba(0,0,0,0.6);
}}
.wf-segment:hover {{ opacity: 0.85; transform: scaleY(1.15); z-index: 10; }}
.wf-tool-row {{ display: flex; align-items: center; margin-bottom: 2px; min-height: 20px; }}
.wf-tool-label {{ width: 80px; flex-shrink: 0; font-size: 10px; color: var(--border); text-align: right; padding-right: 10px; }}
.wf-tool-bar {{ height: 18px; border-radius: 2px; font-size: 9px; color: #fff; display: flex; align-items: center; padding: 0 4px; overflow: hidden; white-space: nowrap; }}

/* Toggle */
.toggle-row {{ display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }}
.toggle-row label {{ font-size: 12px; color: var(--text2); cursor: pointer; display: flex; align-items: center; gap: 4px; }}
.toggle-row input {{ cursor: pointer; }}

/* Context chart */
.ctx-bar-group {{ display: flex; align-items: center; margin-bottom: 4px; }}
.ctx-label {{ width: 60px; font-size: 11px; color: var(--text2); text-align: right; padding-right: 8px; flex-shrink: 0; }}
.ctx-bar-wrap {{ flex: 1; display: flex; height: 16px; border-radius: 2px; overflow: hidden; }}
.ctx-bar {{ height: 100%; }}
.ctx-value {{ font-size: 10px; color: var(--text2); padding-left: 6px; flex-shrink: 0; width: 70px; }}

/* Tool table */
.tool-table {{ width: 100%; font-size: 12px; }}
.tool-table td {{ padding: 4px 0; }}
.tool-table .tool-name {{ color: var(--text); max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
.tool-table .tool-bar-cell {{ width: 100%; }}
.tool-table .tool-bar {{ height: 14px; border-radius: 2px; min-width: 2px; }}
.tool-table .tool-tokens {{ color: var(--text2); text-align: right; white-space: nowrap; padding-left: 8px; }}

/* Donut */
.donut-container {{ display: flex; align-items: center; gap: 20px; justify-content: center; }}
.donut-legend {{ font-size: 12px; }}
.donut-legend-item {{ display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }}
.donut-swatch {{ width: 10px; height: 10px; border-radius: 2px; }}
.donut-legend-value {{ color: var(--text2); }}

/* Tooltip */
#tooltip {{
    position: fixed; background: var(--bg3); border: 1px solid #444c56;
    border-radius: 6px; padding: 10px 14px; font-size: 12px;
    pointer-events: none; display: none; z-index: 1000; max-width: 350px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.5);
}}
#tooltip .tt-title {{ color: var(--text-bright); font-weight: 600; margin-bottom: 4px; }}
#tooltip .tt-detail {{ color: var(--accent); }}
#tooltip .tt-sub {{ color: var(--text2); font-size: 11px; margin-top: 2px; }}

@media (max-width: 900px) {{
    .panels {{ grid-template-columns: 1fr; }}
}}
</style>
</head>
<body>
<div class="container">

<h1>{html_mod.escape(title)}</h1>
<div class="subtitle" id="subtitle"></div>

<div class="stats" id="stats-bar"></div>

<div class="panels">
    <!-- Main waterfall -->
    <div class="panel panel-full">
        <div class="panel-title" id="waterfall-title">Timeline — Output Tokens per Turn</div>
        <div class="toggle-row">
            <label><input type="checkbox" id="show-context" onchange="renderWaterfall()"> Show input/context tokens</label>
            <label><input type="checkbox" id="show-tools" checked onchange="renderWaterfall()"> Expand tool calls</label>
            <label><input type="checkbox" id="show-time" onchange="renderWaterfall()"> Wall-clock time</label>
        </div>
        <div class="waterfall" id="waterfall"></div>
    </div>

    <!-- Aggregate breakdown -->
    <div class="panel">
        <div class="panel-title">Output Token Breakdown</div>
        <div id="donut-chart"></div>
    </div>

    <!-- Context growth -->
    <div class="panel">
        <div class="panel-title">Input Cost per Turn</div>
        <div id="context-chart"></div>
    </div>

    <!-- Top tools -->
    <div class="panel panel-full">
        <div class="panel-title">Top Token Consumers</div>
        <div id="tool-table"></div>
    </div>
</div>

</div>

<div id="tooltip">
    <div class="tt-title"></div>
    <div class="tt-detail"></div>
    <div class="tt-sub"></div>
</div>

<script>
const DATA = {data_json};
const COLORS = {colors_json};

const fmt = n => n.toLocaleString();
const pct = (n, total) => total > 0 ? ((n / total) * 100).toFixed(1) + '%' : '0%';

// --- Stats bar ---
function renderStats() {{
    const t = DATA.totals;
    const cacheRatio = t.input > 0 ? ((t.cache / t.input) * 100).toFixed(0) : 0;
    const el = document.getElementById('stats-bar');
    const stats = [
        ['Output Tokens', fmt(t.output), 'agent produced'],
        ['Thinking', fmt(t.thinking), pct(t.thinking, t.output) + ' of output'],
        ['Tool Calls', t.toolCalls, fmt(t.tool) + ' tokens'],
        ['Input Tokens', fmt(t.input), cacheRatio + '% cached'],
        ['Total Cost', fmt(t.input + t.output), 'in + out'],
    ];
    if (t.durationMs > 0) {{
        const wallSec = (t.durationMs / 1000).toFixed(1);
        const apiSec = ((t.durationApiMs || 0) / 1000).toFixed(1);
        stats.push(['Wall Time', wallSec + 's', apiSec + 's model']);
    }}
    el.innerHTML = stats.map(([label, value, sub]) => `
        <div class="stat">
            <div class="stat-label">${{label}}</div>
            <div class="stat-value">${{value}}</div>
            <div class="stat-sub">${{sub}}</div>
        </div>
    `).join('');
    document.getElementById('subtitle').textContent =
        DATA.model ? `Model: ${{DATA.model}}` : '';
}}

// --- Tooltip ---
const tooltip = document.getElementById('tooltip');
function showTooltip(e, title, detail, sub) {{
    tooltip.style.display = 'block';
    tooltip.style.left = (e.clientX + 14) + 'px';
    tooltip.style.top = (e.clientY - 10) + 'px';
    tooltip.querySelector('.tt-title').textContent = title;
    tooltip.querySelector('.tt-detail').textContent = detail;
    tooltip.querySelector('.tt-sub').textContent = sub || '';
}}
function hideTooltip() {{ tooltip.style.display = 'none'; }}

// --- Waterfall ---
const hasTimeData = DATA.turns.some(t => t.durationMs > 0);
// Hide time toggle if no duration data
if (!hasTimeData) {{
    document.getElementById('show-time').parentElement.style.display = 'none';
}}

function renderWaterfall() {{
    const el = document.getElementById('waterfall');
    const showCtx = document.getElementById('show-context').checked;
    const showTools = document.getElementById('show-tools').checked;
    const showTime = document.getElementById('show-time').checked && hasTimeData;
    const titleEl = document.getElementById('waterfall-title');
    titleEl.textContent = showTime
        ? 'Timeline — Wall-Clock Time per Turn'
        : 'Timeline — Output Tokens per Turn';

    if (showTime) {{
        return renderWaterfallTime(el, showTools);
    }}

    // Determine max width for scaling
    let maxTokens = 0;
    DATA.turns.forEach(turn => {{
        let w = turn.thinking + turn.text + turn.toolTokens;
        if (showCtx) w += turn.inputTokens;
        if (w > maxTokens) maxTokens = w;
    }});

    let html = '';
    const totalOutput = DATA.totals.output;

    DATA.turns.forEach((turn, i) => {{
        const segments = [];
        let x = 0;

        if (turn.thinking > 0) {{
            segments.push({{ name: 'Thinking', tokens: turn.thinking, color: COLORS.thinking, x }});
            x += turn.thinking;
        }}
        turn.tools.forEach(tool => {{
            const tok = tool.totalTokens;
            const cat = tool.category;
            const color = COLORS[cat] || COLORS.other;
            segments.push({{ name: tool.name, tokens: tok, color, x, tool }});
            x += tok;
        }});
        if (turn.text > 0) {{
            segments.push({{ name: 'Text output', tokens: turn.text, color: COLORS.text, x }});
            x += turn.text;
        }}
        if (showCtx && turn.inputTokens > 0) {{
            if (turn.cacheRead > 0) {{
                segments.push({{ name: 'Cache hit', tokens: turn.cacheRead, color: COLORS.cache, x }});
                x += turn.cacheRead;
            }}
            if (turn.freshInput > 0) {{
                segments.push({{ name: 'Fresh input', tokens: turn.freshInput, color: COLORS.fresh, x }});
                x += turn.freshInput;
            }}
        }}

        const rowTotal = x;
        const scale = maxTokens > 0 ? 100 / maxTokens : 0;

        html += `<div class="wf-row">`;
        html += `<div class="wf-label">Turn ${{turn.index}}</div>`;
        html += `<div class="wf-bar-container">`;
        segments.forEach(seg => {{
            const left = (seg.x / maxTokens * 100).toFixed(3);
            const width = (seg.tokens / maxTokens * 100).toFixed(3);
            const label = width > 5 ? seg.name : '';
            html += `<div class="wf-segment" style="left:${{left}}%;width:${{width}}%;background:${{seg.color}}"
                onmousemove="showTooltip(event, '${{seg.name.replace(/'/g, "\\\\'"  )}}', '${{fmt(seg.tokens)}} tokens (${{pct(seg.tokens, totalOutput)}} of output)', 'Turn ${{turn.index}}')"
                onmouseleave="hideTooltip()"
            >${{label}}</div>`;
        }});
        html += `</div></div>`;

        // Expanded tool calls
        if (showTools && turn.tools.length > 0) {{
            turn.tools.forEach(tool => {{
                const toolPct = (tool.totalTokens / maxTokens * 100).toFixed(3);
                const cat = tool.category;
                const color = COLORS[cat] || COLORS.other;
                html += `<div class="wf-tool-row">`;
                html += `<div class="wf-tool-label">${{tool.category}}</div>`;
                html += `<div class="wf-tool-bar" style="width:${{toolPct}}%;background:${{color}};opacity:0.7"
                    onmousemove="showTooltip(event, '${{tool.name.replace(/'/g, "\\\\'")}}', '${{fmt(tool.totalTokens)}} tokens', '${{tool.category}}')"
                    onmouseleave="hideTooltip()"
                >${{tool.name}}</div>`;
                html += `</div>`;

                // Children (sub-agent tools)
                if (tool.children && tool.children.length > 0) {{
                    tool.children.forEach(child => {{
                        const childPct = (child.totalTokens / maxTokens * 100).toFixed(3);
                        const ccolor = COLORS[child.category] || COLORS.other;
                        html += `<div class="wf-tool-row" style="padding-left: 20px;">`;
                        html += `<div class="wf-tool-label" style="width:60px">  \u2514\u2500</div>`;
                        html += `<div class="wf-tool-bar" style="width:${{childPct}}%;background:${{ccolor}};opacity:0.5"
                            onmousemove="showTooltip(event, '${{child.name.replace(/'/g, "\\\\'")}}', '${{fmt(child.totalTokens)}} tokens', 'sub-agent \u2192 ${{child.category}}')"
                            onmouseleave="hideTooltip()"
                        >${{child.name}}</div>`;
                        html += `</div>`;
                    }});
                }}
            }});
        }}
    }});

    el.innerHTML = html;
}}

// --- Time-based waterfall ---
function renderWaterfallTime(el, showTools) {{
    const maxMs = Math.max(...DATA.turns.map(t => t.durationMs || 0), 1);
    const totalMs = DATA.totals.durationMs || 1;
    let html = '';

    DATA.turns.forEach((turn) => {{
        const dur = turn.durationMs || 0;
        const apiMs = turn.durationApiMs || 0;
        const overheadMs = dur - apiMs;
        if (dur === 0) return;

        const secs = (dur / 1000).toFixed(1);
        const apiPct = dur > 0 ? ((apiMs / dur) * 100).toFixed(0) : 0;

        html += `<div class="wf-row">`;
        html += `<div class="wf-label">Turn ${{turn.index}}</div>`;
        html += `<div class="wf-bar-container">`;

        // API/model time bar
        if (apiMs > 0) {{
            const w = (apiMs / maxMs * 100).toFixed(3);
            html += `<div class="wf-segment" style="left:0;width:${{w}}%;background:${{COLORS.thinking}}"
                onmousemove="showTooltip(event, 'Model time', '${{(apiMs/1000).toFixed(1)}}s (${{apiPct}}% of turn)', 'Turn ${{turn.index}} — ${{secs}}s total')"
                onmouseleave="hideTooltip()"
            >${{w > 8 ? (apiMs/1000).toFixed(1) + 's model' : ''}}</div>`;
        }}

        // Overhead bar
        if (overheadMs > 0) {{
            const left = (apiMs / maxMs * 100).toFixed(3);
            const w = (overheadMs / maxMs * 100).toFixed(3);
            html += `<div class="wf-segment" style="left:${{left}}%;width:${{w}}%;background:${{COLORS.bash}};opacity:0.7"
                onmousemove="showTooltip(event, 'Overhead', '${{(overheadMs/1000).toFixed(1)}}s (tool execution, network)', 'Turn ${{turn.index}} — ${{secs}}s total')"
                onmouseleave="hideTooltip()"
            >${{w > 8 ? (overheadMs/1000).toFixed(1) + 's overhead' : ''}}</div>`;
        }}

        html += `</div></div>`;

        // Tool calls (in time mode, show token counts as secondary info)
        if (showTools && turn.tools.length > 0) {{
            turn.tools.forEach(tool => {{
                const toolPct = (tool.totalTokens / Math.max(...DATA.turns.map(t => t.thinking + t.text + t.toolTokens), 1) * 100).toFixed(3);
                const cat = tool.category;
                const color = COLORS[cat] || COLORS.other;
                html += `<div class="wf-tool-row">`;
                html += `<div class="wf-tool-label">${{tool.category}}</div>`;
                html += `<div class="wf-tool-bar" style="width:${{Math.min(toolPct, 100)}}%;background:${{color}};opacity:0.5"
                    onmousemove="showTooltip(event, '${{tool.name.replace(/'/g, "\\\\'")}}', '${{fmt(tool.totalTokens)}} tokens', '${{tool.category}}')"
                    onmouseleave="hideTooltip()"
                >${{tool.name}}</div>`;
                html += `</div>`;
            }});
        }}
    }});

    // Summary line
    const totalSecs = (totalMs / 1000).toFixed(1);
    const apiTotal = (DATA.totals.durationApiMs || 0) / 1000;
    const overTotal = ((totalMs - (DATA.totals.durationApiMs || 0)) / 1000).toFixed(1);
    html += `<div style="margin-top:8px;font-size:12px;color:var(--text2)">Total: ${{totalSecs}}s wall / ${{apiTotal.toFixed(1)}}s model / ${{overTotal}}s overhead</div>`;

    el.innerHTML = html;
}}

// --- Donut chart ---
function renderDonut() {{
    const el = document.getElementById('donut-chart');
    const t = DATA.totals;
    const slices = [
        {{ name: 'Thinking', value: t.thinking, color: COLORS.thinking }},
        {{ name: 'Text output', value: t.text, color: COLORS.text }},
    ];
    // Add tool categories
    Object.entries(DATA.categoryTokens).forEach(([cat, tokens]) => {{
        const catNames = {{ read: 'File reads', write: 'File writes', bash: 'Shell commands', search: 'Search', agent: 'Sub-agents', other: 'Other tools' }};
        slices.push({{ name: catNames[cat] || cat, value: tokens, color: COLORS[cat] || COLORS.other }});
    }});

    const total = slices.reduce((s, x) => s + x.value, 0);
    if (total === 0) {{ el.innerHTML = '<p>No output tokens</p>'; return; }}

    // SVG donut
    const size = 140, cx = size/2, cy = size/2, r = 55, r2 = 35;
    let angle = -Math.PI / 2;
    let paths = '';

    slices.forEach(slice => {{
        if (slice.value === 0) return;
        const frac = slice.value / total;
        const endAngle = angle + frac * Math.PI * 2;
        const large = frac > 0.5 ? 1 : 0;
        const x1 = cx + r * Math.cos(angle), y1 = cy + r * Math.sin(angle);
        const x2 = cx + r * Math.cos(endAngle), y2 = cy + r * Math.sin(endAngle);
        const x3 = cx + r2 * Math.cos(endAngle), y3 = cy + r2 * Math.sin(endAngle);
        const x4 = cx + r2 * Math.cos(angle), y4 = cy + r2 * Math.sin(angle);
        paths += `<path d="M${{x1}},${{y1}} A${{r}},${{r}} 0 ${{large}} 1 ${{x2}},${{y2}} L${{x3}},${{y3}} A${{r2}},${{r2}} 0 ${{large}} 0 ${{x4}},${{y4}} Z" fill="${{slice.color}}" stroke="var(--bg2)" stroke-width="1.5"
            onmousemove="showTooltip(event, '${{slice.name}}', '${{fmt(slice.value)}} tokens (${{pct(slice.value, total)}})', '')"
            onmouseleave="hideTooltip()" style="cursor:pointer"/>`;
        angle = endAngle;
    }});

    const legend = slices.filter(s => s.value > 0).map(s => `
        <div class="donut-legend-item">
            <span class="donut-swatch" style="background:${{s.color}}"></span>
            <span>${{s.name}}</span>
            <span class="donut-legend-value">${{pct(s.value, total)}}</span>
        </div>
    `).join('');

    el.innerHTML = `
        <div class="donut-container">
            <svg width="${{size}}" height="${{size}}" viewBox="0 0 ${{size}} ${{size}}">${{paths}}
                <text x="${{cx}}" y="${{cy - 6}}" text-anchor="middle" fill="var(--text-bright)" font-size="14" font-weight="700">${{fmt(total)}}</text>
                <text x="${{cx}}" y="${{cy + 10}}" text-anchor="middle" fill="var(--text2)" font-size="10">output tokens</text>
            </svg>
            <div class="donut-legend">${{legend}}</div>
        </div>
    `;
}}

// --- Context growth chart ---
function renderContextChart() {{
    const el = document.getElementById('context-chart');
    const maxInput = Math.max(...DATA.turns.map(t => t.inputTokens), 1);

    let html = '';
    DATA.turns.forEach(turn => {{
        if (turn.inputTokens === 0) return;
        const cachePct = (turn.cacheRead / turn.inputTokens * 100).toFixed(0);
        const cacheW = (turn.cacheRead / maxInput * 100).toFixed(1);
        const freshW = (turn.freshInput / maxInput * 100).toFixed(1);

        html += `<div class="ctx-bar-group">`;
        html += `<div class="ctx-label">T${{turn.index}}</div>`;
        html += `<div class="ctx-bar-wrap">`;
        html += `<div class="ctx-bar" style="width:${{cacheW}}%;background:${{COLORS.cache}}"
            onmousemove="showTooltip(event, 'Cache hit', '${{fmt(turn.cacheRead)}} tokens', 'Turn ${{turn.index}}')"
            onmouseleave="hideTooltip()"></div>`;
        html += `<div class="ctx-bar" style="width:${{freshW}}%;background:${{COLORS.fresh}}"
            onmousemove="showTooltip(event, 'Fresh input', '${{fmt(turn.freshInput)}} tokens', 'Turn ${{turn.index}}')"
            onmouseleave="hideTooltip()"></div>`;
        html += `</div>`;
        html += `<div class="ctx-value">${{fmt(turn.inputTokens)}} (${{cachePct}}%)</div>`;
        html += `</div>`;
    }});
    el.innerHTML = html;
}}

// --- Top tools table ---
function renderToolTable() {{
    const el = document.getElementById('tool-table');
    if (DATA.topTools.length === 0) {{
        el.innerHTML = '<p style="color:var(--text2);font-size:12px">No tool calls</p>';
        return;
    }}
    const maxTok = DATA.topTools[0].tokens;
    const totalTool = DATA.totals.tool;

    let html = '<table class="tool-table">';
    DATA.topTools.forEach(tool => {{
        const barW = (tool.tokens / maxTok * 100).toFixed(1);
        // Determine color from name
        let color = COLORS.other;
        if (tool.name.startsWith('Read')) color = COLORS.read;
        else if (tool.name.startsWith('Edit') || tool.name.startsWith('Write')) color = COLORS.write;
        else if (tool.name.startsWith('Bash')) color = COLORS.bash;
        else if (tool.name.startsWith('Grep') || tool.name.startsWith('Glob')) color = COLORS.search;
        else if (tool.name.startsWith('Agent')) color = COLORS.agent;

        html += `<tr>
            <td class="tool-name" title="${{tool.name}}">${{tool.name}}</td>
            <td class="tool-bar-cell"><div class="tool-bar" style="width:${{barW}}%;background:${{color}}"></div></td>
            <td class="tool-tokens">${{fmt(tool.tokens)}} (${{pct(tool.tokens, totalTool)}})</td>
        </tr>`;
    }});
    html += '</table>';
    el.innerHTML = html;
}}

// --- Render all ---
renderStats();
renderWaterfall();
renderDonut();
renderContextChart();
renderToolTable();
</script>
</body>
</html>"""
