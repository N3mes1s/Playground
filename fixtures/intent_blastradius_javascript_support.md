# Add JavaScript / TypeScript support to `blast-radius-prediction`

## What

Extend `mirofish_lab/repo.py` so that `extract_symbols()`,
`grep_callers()`, and the diff-to-symbol mapping work for `.js` /
`.ts` / `.tsx` / `.jsx` files in addition to `.py`. Use **tree-sitter**
for AST parsing (single dep, language-pluggable) and grep over a
keyword set the tree-sitter parse generates.

## Why

- Most of the interesting public PRs we've used as examples
  (recursive-lm-security-audit's audit targets like Flowise, n8n,
  Juice Shop) are TypeScript. The `blast-radius-prediction` experiment
  currently silently no-ops on them because the Python AST extractor
  finds zero symbols.
- Tree-sitter has good Python bindings and grammars for JS/TS already;
  this is mostly plumbing.

## Scope

- `mirofish_lab/repo.py`:
  - New `_LANG_PARSERS` registry mapping suffix → tree-sitter grammar.
  - `extract_symbols()` dispatches on suffix; falls back to the
    existing `ast.parse` path for `.py`.
  - `python_files()` renamed to `source_files()` with a `langs` arg
    (default keeps old behaviour for `.py`).
  - New helpers `js_symbols(file)` / `ts_symbols(file)`.
- `blast-radius-prediction/cli.py`: no changes if the helpers stay
  signature-compatible.
- New optional dep in `requirements.txt`: `tree-sitter`,
  `tree-sitter-python`, `tree-sitter-javascript`,
  `tree-sitter-typescript`.

## Constraints

- **Python path unchanged**: existing `.py` extraction must remain
  byte-identical so `blast-radius-prediction/reports/sample.md` is
  reproducible.
- **No build step**: `pip install -r requirements.txt` must produce a
  working setup. tree-sitter ships pre-built wheels for the four
  grammars we need.
- **Graceful fallback**: if tree-sitter fails to import (older
  Python, missing wheel), the JS/TS path silently degrades to "no
  symbols" with a clear log warning, not a crash.

## Out of scope

- Go, Rust, Java support (separate experiment).
- Type-aware analysis (TypeScript tsserver integration is a much
  bigger commitment).

## Affected stakeholders

- `blast-radius-prediction` (the change)
- `mirofish_lab` (repo helpers)
- Users who run blast-radius against JS/TS repos
