use crate::flamegraph::VizData;

pub fn render_html(viz: &VizData, title: &str) -> String {
    let data_json = serde_json::to_string(viz).unwrap_or_default();
    let colors_json = r###"{"thinking":"#e8524a","text":"#4a90d9","read":"#50b86c","write":"#f5a623","bash":"#9b59b6","search":"#2ecc71","agent":"#e74c3c","other":"#3498db","cache":"#555555","fresh":"#888888"}"###;

    format!(r####"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
:root {{ --bg: #0d1117; --bg2: #161b22; --bg3: #1c2128; --border: #30363d; --text: #c9d1d9; --text2: #8b949e; --text-bright: #f0f6fc; --accent: #58a6ff; }}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: var(--bg); color: var(--text); }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
h1 {{ font-size: 20px; color: var(--text-bright); margin-bottom: 4px; }}
.subtitle {{ font-size: 13px; color: var(--text2); margin-bottom: 16px; }}
.stats {{ display: flex; gap: 12px; margin-bottom: 20px; flex-wrap: wrap; }}
.stat {{ background: var(--bg2); padding: 10px 16px; border-radius: 8px; border: 1px solid var(--border); min-width: 120px; }}
.stat-label {{ color: var(--text2); font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; }}
.stat-value {{ color: var(--text-bright); font-size: 20px; font-weight: 700; margin-top: 2px; }}
.stat-sub {{ color: var(--text2); font-size: 11px; }}
.panels {{ display: grid; grid-template-columns: 1fr 340px; gap: 16px; margin-bottom: 20px; }}
.panel {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
.panel-title {{ font-size: 13px; color: var(--text2); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 12px; font-weight: 600; }}
.panel-full {{ grid-column: 1 / -1; }}
.wf-row {{ display: flex; align-items: center; margin-bottom: 3px; min-height: 28px; }}
.wf-label {{ width: 80px; flex-shrink: 0; font-size: 12px; color: var(--text2); text-align: right; padding-right: 10px; }}
.wf-bar-container {{ flex: 1; position: relative; height: 26px; }}
.wf-segment {{ position: absolute; height: 26px; border-radius: 3px; cursor: pointer; transition: opacity 0.1s; display: flex; align-items: center; padding: 0 4px; font-size: 10px; color: #fff; overflow: hidden; white-space: nowrap; text-shadow: 0 1px 2px rgba(0,0,0,0.6); }}
.wf-segment:hover {{ opacity: 0.85; z-index: 10; }}
.toggle-row {{ display: flex; gap: 8px; margin-bottom: 12px; align-items: center; }}
.toggle-row label {{ font-size: 12px; color: var(--text2); cursor: pointer; display: flex; align-items: center; gap: 4px; }}
#tooltip {{ position: fixed; background: var(--bg3); border: 1px solid #444c56; border-radius: 6px; padding: 10px 14px; font-size: 12px; pointer-events: none; display: none; z-index: 1000; max-width: 350px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
#tooltip .tt-title {{ color: var(--text-bright); font-weight: 600; margin-bottom: 4px; }}
#tooltip .tt-detail {{ color: var(--accent); }}
@media (max-width: 900px) {{ .panels {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<div class="container">
<h1>{title}</h1>
<div class="subtitle" id="subtitle"></div>
<div class="stats" id="stats-bar"></div>
<div class="panels">
<div class="panel panel-full">
<div class="panel-title" id="waterfall-title">Timeline — Output Tokens per Turn</div>
<div class="toggle-row">
<label><input type="checkbox" id="show-context" onchange="renderWaterfall()"> Show input tokens</label>
<label><input type="checkbox" id="show-time" onchange="renderWaterfall()"> Wall-clock time</label>
</div>
<div id="waterfall"></div>
</div>
</div>
</div>
<div id="tooltip"><div class="tt-title"></div><div class="tt-detail"></div></div>
<script>
const DATA = {data_json};
const COLORS = {colors_json};
const fmt = n => n.toLocaleString();
const pct = (n, t) => t > 0 ? ((n/t)*100).toFixed(1)+'%' : '0%';

function renderStats() {{
  const t = DATA.totals;
  const cr = t.input > 0 ? ((t.cache/t.input)*100).toFixed(0) : 0;
  const stats = [['Output', fmt(t.output), 'tokens'],['Thinking', fmt(t.thinking), pct(t.thinking,t.output)],['Tools', t.toolCalls, fmt(t.tool)+' tok'],['Input', fmt(t.input), cr+'% cached']];
  if (t.durationMs > 0) stats.push(['Time', (t.durationMs/1000).toFixed(1)+'s', (t.durationApiMs/1000).toFixed(1)+'s model']);
  document.getElementById('stats-bar').innerHTML = stats.map(([l,v,s]) => `<div class="stat"><div class="stat-label">${{l}}</div><div class="stat-value">${{v}}</div><div class="stat-sub">${{s}}</div></div>`).join('');
  document.getElementById('subtitle').textContent = DATA.model ? `Model: ${{DATA.model}}` : '';
}}

const tooltip = document.getElementById('tooltip');
function showTooltip(e, title, detail) {{ tooltip.style.display='block'; tooltip.style.left=(e.clientX+14)+'px'; tooltip.style.top=(e.clientY-10)+'px'; tooltip.querySelector('.tt-title').textContent=title; tooltip.querySelector('.tt-detail').textContent=detail; }}
function hideTooltip() {{ tooltip.style.display='none'; }}

const hasTime = DATA.turns.some(t => t.durationMs > 0);
if (!hasTime) document.getElementById('show-time').parentElement.style.display='none';

function renderWaterfall() {{
  const el = document.getElementById('waterfall');
  const showCtx = document.getElementById('show-context').checked;
  const showTime = document.getElementById('show-time').checked && hasTime;
  document.getElementById('waterfall-title').textContent = showTime ? 'Timeline — Wall-Clock Time per Turn' : 'Timeline — Output Tokens per Turn';

  if (showTime) {{ renderTimeWaterfall(el); return; }}
  let maxT = 0;
  DATA.turns.forEach(t => {{ let w = t.thinking+t.text+t.toolTokens; if(showCtx) w+=t.inputTokens; if(w>maxT) maxT=w; }});
  let html = '';
  DATA.turns.forEach(t => {{
    let segs = [], x = 0;
    if(t.thinking>0) {{ segs.push({{n:'Thinking',tk:t.thinking,c:COLORS.thinking,x}}); x+=t.thinking; }}
    t.tools.forEach(tool => {{ const c=COLORS[tool.category]||COLORS.other; segs.push({{n:tool.name,tk:tool.totalTokens,c,x}}); x+=tool.totalTokens; }});
    if(t.text>0) {{ segs.push({{n:'Text',tk:t.text,c:COLORS.text,x}}); x+=t.text; }}
    if(showCtx && t.inputTokens>0) {{
      if(t.cacheRead>0) {{ segs.push({{n:'Cache',tk:t.cacheRead,c:COLORS.cache,x}}); x+=t.cacheRead; }}
      if(t.freshInput>0) {{ segs.push({{n:'Fresh',tk:t.freshInput,c:COLORS.fresh,x}}); x+=t.freshInput; }}
    }}
    html += `<div class="wf-row"><div class="wf-label">Turn ${{t.index}}</div><div class="wf-bar-container">`;
    segs.forEach(s => {{
      const l=(s.x/maxT*100).toFixed(2), w=(s.tk/maxT*100).toFixed(2);
      html += `<div class="wf-segment" style="left:${{l}}%;width:${{w}}%;background:${{s.c}}" onmousemove="showTooltip(event,'${{s.n}}','${{fmt(s.tk)}} tokens')" onmouseleave="hideTooltip()">${{w>5?s.n:''}}</div>`;
    }});
    html += '</div></div>';
  }});
  el.innerHTML = html;
}}

function renderTimeWaterfall(el) {{
  const maxMs = Math.max(...DATA.turns.map(t=>t.durationMs||0),1);
  let html = '';
  DATA.turns.forEach(t => {{
    if(!t.durationMs) return;
    const api=t.durationApiMs||0, over=t.durationMs-api;
    html += `<div class="wf-row"><div class="wf-label">Turn ${{t.index}}</div><div class="wf-bar-container">`;
    if(api>0) {{ const w=(api/maxMs*100).toFixed(2); html += `<div class="wf-segment" style="left:0;width:${{w}}%;background:${{COLORS.thinking}}" onmousemove="showTooltip(event,'Model','${{(api/1000).toFixed(1)}}s')" onmouseleave="hideTooltip()">${{w>8?(api/1000).toFixed(1)+'s':''}}</div>`; }}
    if(over>0) {{ const l=(api/maxMs*100).toFixed(2), w=(over/maxMs*100).toFixed(2); html += `<div class="wf-segment" style="left:${{l}}%;width:${{w}}%;background:${{COLORS.bash}};opacity:0.7" onmousemove="showTooltip(event,'Overhead','${{(over/1000).toFixed(1)}}s')" onmouseleave="hideTooltip()"></div>`; }}
    html += '</div></div>';
  }});
  el.innerHTML = html;
}}

renderStats(); renderWaterfall();
</script>
</body>
</html>"####, title = title, data_json = data_json, colors_json = colors_json)
}
