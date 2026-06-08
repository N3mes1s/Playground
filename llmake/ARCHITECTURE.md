# Architecture

llmake is a cached, DAG-based build system for LLM inference workflows that treats notes and specs as source. It reads a declarative workflow manifest, expands templated targets into a concrete step graph, and executes them in topological order while memoizing results in a content-addressable cache. The architecture separates parsing, planning, rendering, graph ordering, caching, and execution into small, testable modules.

## Data flow

A build request starts in `cli.py`, which parses arguments and calls `load_workflow()` (from `spec.py`, re-exported via `__init__.py`) to read the YAML manifest. The `runner.py` build engine then calls `plan.expand()` to resolve `foreach` patterns and authored dependencies into concrete `Step` instances, and uses `graph.py` to topologically sort the target DAG and detect cycles. For each step, `runner.py` loads workspace material via `context.py`, renders the final prompt via `render.py`, and checks `cache.py` for a fresh, content-addressed entry; cache misses are dispatched to the provider, atomically written to disk, and recorded in the cache. After the build, `cli.py` can delegate to `export.py` to bundle artifacts into a standalone HTML report or to `snapshot.py` to tag the build directory in git.

## Modules

### __init__.py

- Acts as the package’s public API facade, re-exporting `load_workflow` (from `.spec`), `build` and `status` (from `.runner`), and `__version__`.
- Declares `__all__` to explicitly define the stable public interface, preventing leakage of internal submodule symbols.
- Hosts the module-level docstring that establishes the project’s purpose: a cached, DAG-based build system for LLM inference workflows where notes and specs are treated as source.

### cache.py

- **Responsibility**: Implements a content-addressable build cache that enables incremental, reproducible builds for llmake. Each target's artifact is keyed by a hash of all inputs that can affect its output (prompt, provider, model, parameters, and transitive upstream artifacts), allowing downstream targets to recompute only when dependencies change.
- **`compute_key()`**: Deterministically generates a SHA-256 cache key from a target's fully-rendered prompt, provider, model, kind, params, and sorted upstream keys—ensuring that identical inputs always produce identical hashes.
- **`Entry`**: A dataclass representing a cached target with its key, artifact path, metadata (provider, model, kind, timestamp), dependency lists (`inputs`, `needs`), and arbitrary `meta` dict.
- **`Cache`**: The on-disk build index manager that loads from and persists to `.llmake/cache.json`. Provides `get`/`put` for entries, `is_fresh()` to verify a target's key matches and its artifact still exists on disk, and `clear()` to wipe the cache.

### cli.py

- **CLI entry point and argument parsing**: Defines the `llmake` command-line surface via `build_parser()`, which registers subcommands (`build`, `status`, `graph`, `providers`, `snapshot`, `snapshots`, `export`, `clean`) and global options (`-C`, `--workflow`, `-v`), and `main()` which parses arguments, sets logging verbosity, and dispatches to the appropriate `cmd_*` handler.
- **Workflow loading**: The private `_load()` helper resolves the manifest path from CLI flags and returns a parsed workflow object by calling `load_workflow()`.
- **Build & inspection commands**: `cmd_build()` invokes `runner.build()` for incremental compilation, tracks token usage and cost, and reports results. `cmd_status()` runs a dry-run to label targets as cached or stale, while `cmd_graph()` uses `plan.expand()` and `graph.build_plan()` to print the dependency DAG.
- **Lifecycle & utility commands**: `cmd_providers()` lists available inference backends; `cmd_snapshot()` / `cmd_snapshots()` and `cmd_export()` delegate to the `snapshot` and `export` modules for artifact versioning and HTML bundling; `cmd_clean()` removes the build directory and cache file.

### context.py

- **Responsibility**: Isolates source-material handling from the build engine by resolving manifest glob patterns into concrete file contents, allowing the input layer to grow (e.g., assets, URLs) independently.
- **File loading**: `load_inputs` and `load_context` are the public entry points that delegate to the private `_expand` helper to walk globs relative to the `Workflow` root, returning a dictionary of relative POSIX paths to file text; `load_inputs` optionally accepts override patterns or falls back to the manifest's `inputs:` list.
- **Content hashing**: `content_hash` computes a SHA256 hex digest of a UTF-8 string for cache keys or content identity.

### export.py

- **Responsibility:** Bundles compiled artifacts and their build provenance into a single, self-contained HTML file with zero external assets or JavaScript, satisfying the "shareable output" requirement for email, wikis, or direct publication.
- **`export_html(wf, out_path)`**: Core function that reads the `Workflow` spec and `Cache` to generate a standalone HTML report. It iterates over cached entries, injects each artifact’s body alongside metadata (provider, model, build time, inputs), and writes the result to disk using only stdlib (`html.escape`, `pathlib`).
- **Output handling:** Automatically creates missing parent directories for the output path and gracefully marks artifacts as "(artifact missing)" when the expected file is not present on disk.

### graph.py

- Provides pure, dependency-free graph algorithms to convert a workflow's target dependencies into a buildable DAG, isolating ordering logic for easy unit testing.
- `topo_order(deps)` — topologically sorts targets so dependencies are built first, raising `CycleError` with the full cycle path if a circular dependency is detected.
- `reachable(deps, goals)` — computes the transitive closure of targets required to satisfy one or more goal targets.
- `build_plan(deps, goals)` — returns the topologically ordered subset of targets that must actually be built, or the entire graph if no goals are specified.

### plan.py

- Expands authored workflow targets into concrete, schedulable `Step` objects, handling `foreach` fan-out (one step per matched file) and resolving downstream dependencies so the runner, DAG, cache, and providers see only a flat step graph.
- **`Step`** dataclass represents a single concrete buildable unit, tracking its unique id, authored target group, concrete dependency names (`deps`), authored need names (`need_groups`), and optional `foreach` item details (`item_name`, `item_path`).
- **`expand()`** performs a two-pass expansion over a `Workflow`: first it creates `Step` instances and a group-to-members map (globbing the workspace for `foreach` patterns), then it resolves authored `needs` into concrete step dependencies via the group map, returning `(steps, groups)` dictionaries.
- **`resolve_goals()`** translates user-requested target names into concrete step names by expanding authored group names through the group map, or passing through names that are already concrete step identifiers.

### render.py

- **Explicit `{{...}}` templating engine** that substitutes workspace material into prompt text. It supports placeholders for inputs (`{{input}}`, `{{input:PATH}}`), shared context (`{{context}}`), upstream artifacts (`{{needs:NAME}}`), and foreach items (`{{item}}`, `{{item_name}}`), remaining decoupled from the runner so substitution rules are obvious and testable.
- **`render(...)`** performs regex-based replacement over a template string, resolving each placeholder against the provided `inputs`, `context`, `needs`, and optional `item_*` values, leaving unknown placeholders untouched. It tracks whether inputs or needs were referenced and, if not, auto-appends the concatenated material to the output so trivial prompts still receive their full context.
- **`_join(...)`** helper formats material dictionaries into markdown-style sections with headers, used to concatenate entire collections of inputs, context, or needs when no specific path or name argument is provided.

### runner.py

- **Build engine orchestrator** that incrementally compiles a workflow into artifacts. It expands authored targets into concrete steps (including `foreach` fan-outs), walks the step DAG in dependency order, renders prompts against workspace material and upstream artifacts, and atomically writes compiled outputs.
- **`build()`** is the main entry point: it validates the execution plan, checks cache freshness, materializes prompts, dispatches stale steps to the chosen provider, and supports concurrent execution via `_run_parallel()` when `jobs > 1`.
- **`_materialize()`** assembles a step's final prompt from templates, context files, and upstream artifacts; `_run_with_retry()` invokes providers with configurable exponential backoff; `_atomic_write()` persists outputs via temp-file-and-replace.
- **`status()`** performs a dry run that reports build state without invoking providers, while **`StepResult`** records per-step outcomes (built/cached/skipped) and associated metadata.

### snapshot.py

- **Responsibility:** Wraps git to create and list tagged snapshots of build artifacts (defaulting to `build/`) so compile states can be listed, diffed, and restored with standard git tooling. It force-adds paths to bypass `.gitignore` and tags each commit as `llmake/<short-sha>`.
- **`Snapshot` dataclass:** Stores the snapshot tag reference (`ref`), commit message, and ISO timestamp (`when`).
- **`snapshot(root, message, paths=None)`:** Validates a git repo, stages the specified paths, commits with an `llmake snapshot:` prefix, creates (or force-updates) an annotated `llmake/<short-sha>` tag, and returns a `Snapshot`.
- **`list_snapshots(root)`:** Returns all `llmake/*` tags as `Snapshot` objects sorted newest-first by creator date.

### spec.py

- **Workflow manifest loader**: Defines the declarative data model (`Defaults`, `Target`, `Workflow`) and YAML parsing logic for `llmake.yaml`, which serves as the project's Makefile equivalent—declaring the prompt library, source inputs, and the DAG of inference targets.
- **`load_workflow`**: Resolves a file or directory path to a manifest, parses it with `yaml.safe_load`, constructs a `Workflow` object, and applies environment-aware default resolution (falling back to `LLMAKE_PROVIDER` / `LLMAKE_MODEL` before built-in defaults).
- **`_validate` / `SpecError`**: Enforces structural integrity—ensures at least one target exists, every dependency in `needs` references a defined target, and no target lacks a prompt.
- **`resolve_prompt`**: Translates a target's `prompt` field into literal text by checking the named prompt library, reading a file path, or falling back to treating the value as inline literal text.