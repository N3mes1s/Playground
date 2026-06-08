# Architecture

llmake is a cached, DAG-based build system for LLM inference workflows that treats prompts, specifications, and source notes as buildable source code. It incrementally compiles workflow manifests into artifacts by topologically ordering dependencies, rendering templates against workspace material, and caching content-addressable outputs to skip unnecessary recomputation. The architecture cleanly separates graph planning, prompt rendering, context resolution, and execution orchestration behind a unified CLI facade.

## Data flow

A build request enters through `cli.py`, which parses arguments and loads the `llmake.yaml` manifest via `spec.py`. The `runner.py` build engine then takes over: it expands the abstract workflow into concrete executable steps using `plan.py` (handling `foreach` fan-out and dependency resolution), determines a topological build order via `graph.py`, and loads workspace source material through `context.py`. For each step, `render.py` substitutes template placeholders with inputs and upstream artifacts; the runner checks `cache.py` for a fresh, content-addressed entry before dispatching stale work to the LLM provider. Finished artifacts are written atomically back to disk by `runner.py`, after which `cli.py` can optionally invoke `snapshot.py` to tag the build state or `export.py` to bundle results into a standalone HTML report.

## Modules

### `__init__.py`

- Acts as the package’s public API facade, re-exporting `load_workflow` (from `.spec`), `build` and `status` (from `.runner`), and `__version__`.
- Declares `__all__` to explicitly define the stable public interface, preventing leakage of internal submodule symbols.
- Hosts the module-level docstring that establishes the project’s purpose: a cached, DAG-based build system for LLM inference workflows where notes and specs are treated as source.

### `cache.py`

- **Responsibility**: Implements a content-addressable build cache that enables incremental, reproducible builds for llmake. Each target's artifact is keyed by a hash of all inputs that can affect its output (prompt, provider, model, parameters, and transitive upstream artifacts), allowing downstream targets to recompute only when dependencies change.
- **`compute_key()`**: Deterministically generates a SHA-256 cache key from a target's fully-rendered prompt, provider, model, kind, params, and sorted upstream keys—ensuring that identical inputs always produce identical hashes.
- **`Entry`**: A dataclass representing a cached target with its key, artifact path, metadata (provider, model, kind, timestamp), dependency lists (`inputs`, `needs`), and arbitrary `meta` dict.
- **`Cache`**: The on-disk build index manager that loads from and persists to `.llmake/cache.json`. Provides `get`/`put` for entries, `is_fresh()` to verify a target's key matches and its artifact still exists on disk, and `clear()` to wipe the cache.

### `cli.py`

- **Entry point & dispatch.** `build_parser()` constructs the full `argparse` hierarchy with subcommands (`build`, `status`, `graph`, `providers`, `snapshot`, `snapshots`, `export`, `clean`). `main()` parses arguments, configures logging verbosity, and dispatches to the matching `cmd_*` handler, catching `SpecError`, `RuntimeError`, and `KeyError` for clean error reporting.
- **Workflow loading.** `_load()` resolves the workflow directory or explicit manifest path and returns the parsed `llmake.yaml` spec via `load_workflow()`.
- **Command orchestration.** `cmd_build` drives the incremental runner, surfaces `BuildError`, and aggregates token/cost metadata from results; `cmd_status` dry-runs the build to flag stale vs. cached targets; `cmd_graph` prints the dependency DAG and `foreach` expansions; `cmd_snapshot`/`cmd_snapshots` wrap artifact versioning; `cmd_export` bundles artifacts into a shareable HTML file; and `cmd_clean` purges the build directory and cache.

### `context.py`

- **Responsibility**: Isolates source-material handling from the build engine by resolving manifest glob patterns into concrete file contents, allowing the input layer to grow (e.g., assets, URLs) independently.
- **File loading**: `load_inputs` and `load_context` are the public entry points that delegate to the private `_expand` helper to walk globs relative to the `Workflow` root, returning a dictionary of relative POSIX paths to file text; `load_inputs` optionally accepts override patterns or falls back to the manifest's `inputs:` list.
- **Content hashing**: `content_hash` computes a SHA256 hex digest of a UTF-8 string for cache keys or content identity.

### `export.py`

- **Responsibility:** Bundles compiled artifacts and their build provenance into a single, self-contained HTML file with zero external assets or JavaScript, satisfying the "shareable output" requirement for email, wikis, or direct publication.
- **`export_html(wf, out_path)`**: Core function that reads the `Workflow` spec and `Cache` to generate a standalone HTML report. It iterates over cached entries, injects each artifact’s body alongside metadata (provider, model, build time, inputs), and writes the result to disk using only stdlib (`html.escape`, `pathlib`).
- **Output handling:** Automatically creates missing parent directories for the output path and gracefully marks artifacts as "(artifact missing)" when the expected file is not present on disk.

### `graph.py`

- Provides pure, dependency-free graph algorithms to convert a workflow's target dependencies into a buildable DAG, isolating ordering logic for easy unit testing.
- `topo_order(deps)` — topologically sorts targets so dependencies are built first, raising `CycleError` with the full cycle path if a circular dependency is detected.
- `reachable(deps, goals)` — computes the transitive closure of targets required to satisfy one or more goal targets.
- `build_plan(deps, goals)` — returns the topologically ordered subset of targets that must actually be built, or the entire graph if no goals are specified.

### `plan.py`

- **Responsibility**: Expands authored workflow targets into concrete, executable build steps. It handles `foreach` fan-out (creating one step per matched file), resolves downstream dependencies by mapping authored `needs` to concrete step names through a group map, and remains pure with no I/O beyond workspace globbing.
- **`Step`**: A dataclass representing one concrete buildable unit, storing a unique step name, its authored target group, the original `Target` definition, resolved concrete dependency names (`deps`), authored need names (`need_groups`), and optional foreach metadata (`item_name`, `item_path`).
- **`expand()`**: Two-pass function that materializes a `Workflow` into `(steps, groups)`. The first pass creates `Step` instances for each target, expanding `foreach` globs into per-file steps; the second pass wires `deps` by resolving each authored `needs` entry into concrete step names via the group map.
- **`resolve_goals()`**: Translates user-requested goal names from authored target identifiers into concrete step names, expanding group references through the group map so the scheduler receives only executable units.

### `render.py`

- **Explicit `{{...}}` templating engine** that substitutes workspace material into prompt text. It supports placeholders for inputs (`{{input}}`, `{{input:PATH}}`), shared context (`{{context}}`), upstream artifacts (`{{needs:NAME}}`), and foreach items (`{{item}}`, `{{item_name}}`), remaining decoupled from the runner so substitution rules are obvious and testable.
- **`render(...)`** performs regex-based replacement over a template string, resolving each placeholder against the provided `inputs`, `context`, `needs`, and optional `item_*` values, leaving unknown placeholders untouched. It tracks whether inputs or needs were referenced and, if not, auto-appends the concatenated material to the output so trivial prompts still receive their full context.
- **`_join(...)`** helper formats material dictionaries into markdown-style sections with headers, used to concatenate entire collections of inputs, context, or needs when no specific path or name argument is provided.

### `runner.py`

- **Build engine orchestrator** that incrementally compiles a workflow into artifacts. It expands authored targets into concrete steps (including `foreach` fan-outs), walks the step DAG in dependency order, renders prompts against workspace material and upstream artifacts, and atomically writes compiled outputs.
- **`build()`** is the main entry point: it validates the execution plan, checks cache freshness, materializes prompts, dispatches stale steps to the chosen provider, and supports concurrent execution via `_run_parallel()` when `jobs > 1`.
- **`_materialize()`** assembles a step's final prompt from templates, context files, and upstream artifacts; `_run_with_retry()` invokes providers with configurable exponential backoff; `_atomic_write()` persists outputs via temp-file-and-replace.
- **`status()`** performs a dry run that reports build state without invoking providers, while **`StepResult`** records per-step outcomes (built/cached/skipped) and associated metadata.

### `snapshot.py`

- **Responsibility:** Wraps git to create and list tagged snapshots of build artifacts (defaulting to `build/`) so compile states can be listed, diffed, and restored with standard git tooling. It force-adds paths to bypass `.gitignore` and tags each commit as `llmake/<short-sha>`.
- **`Snapshot` dataclass:** Stores the snapshot tag reference (`ref`), commit message, and ISO timestamp (`when`).
- **`snapshot(root, message, paths=None)`:** Validates a git repo