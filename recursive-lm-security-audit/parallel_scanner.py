"""
Parallel scanning engine for large codebases.

Splits a repository into digestible chunks, runs RLM security audits
in parallel across chunks, then synthesizes findings into a unified report.

Architecture:
    1. chunk_source_tree() -- splits repo into logical modules
    2. scan_chunks_parallel() -- runs N concurrent RLM scans
    3. synthesize_reports() -- merges + deduplicates via a final LM pass
"""

import asyncio
import json
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import dspy

from scanner import (
    CodeScanner,
    SOURCE_EXTENSIONS,
    SKIP_DIRS,
    _configure_deno_tls,
    load_source_tree,
)


# ---------------------------------------------------------------------------
# Chunk sizing
# ---------------------------------------------------------------------------

# Target chunk size in characters. Each chunk should be small enough for the
# RLM to explore effectively within its iteration budget.
MAX_CHUNK_CHARS = 2_000_000  # ~2MB of source per chunk


def _tree_size(tree: dict[str, Any]) -> int:
    """Estimate total character count of a source tree dict."""
    total = 0
    for value in tree.values():
        if isinstance(value, dict):
            total += _tree_size(value)
        elif isinstance(value, str):
            total += len(value)
    return total


def _tree_file_count(tree: dict[str, Any]) -> int:
    """Count leaf files in a source tree dict."""
    count = 0
    for value in tree.values():
        if isinstance(value, dict):
            count += _tree_file_count(value)
        else:
            count += 1
    return count


# ---------------------------------------------------------------------------
# Chunking strategies
# ---------------------------------------------------------------------------

def chunk_source_tree(
    tree: dict[str, Any],
    root_name: str = "",
    max_chars: int = MAX_CHUNK_CHARS,
) -> list[tuple[str, dict[str, Any]]]:
    """Split a source tree into chunks that each fit within max_chars.

    Strategy:
      - Top-level directories become individual chunks if they're under the limit.
      - Oversized directories are recursively split into sub-chunks.
      - Tiny directories are merged together into a single chunk.

    Returns:
        List of (chunk_name, subtree_dict) tuples.
    """
    total_size = _tree_size(tree)

    # If the whole tree fits, return it as a single chunk
    if total_size <= max_chars:
        name = root_name or "root"
        return [(name, tree)]

    chunks: list[tuple[str, dict[str, Any]]] = []
    small_items: dict[str, Any] = {}
    small_size = 0

    for key, value in sorted(tree.items()):
        if isinstance(value, dict):
            subtree_size = _tree_size(value)

            if subtree_size > max_chars:
                # Recursively split oversized directories
                sub_chunks = chunk_source_tree(
                    value,
                    root_name=f"{root_name}/{key}" if root_name else key,
                    max_chars=max_chars,
                )
                chunks.extend(sub_chunks)
            elif small_size + subtree_size > max_chars:
                # Flush accumulated small items, then start new batch
                if small_items:
                    chunk_name = root_name or "misc"
                    chunks.append((f"{chunk_name}/batch-{len(chunks)}", small_items))
                    small_items = {}
                    small_size = 0
                small_items[key] = value
                small_size += subtree_size
            else:
                # Accumulate small directories together
                small_items[key] = value
                small_size += subtree_size
        else:
            # Top-level files go into the small items bucket
            file_size = len(value) if isinstance(value, str) else 0
            small_items[key] = value
            small_size += file_size

    # Flush remaining small items
    if small_items:
        chunk_name = root_name or "root-files"
        if len(chunks) == 0:
            chunks.append((chunk_name, small_items))
        else:
            chunks.append((f"{chunk_name}/remaining", small_items))

    return chunks


# ---------------------------------------------------------------------------
# Parallel scanning
# ---------------------------------------------------------------------------

class ChunkReport:
    """Result from scanning a single chunk."""
    chunk_name: str
    report: str
    file_count: int
    char_count: int
    duration_s: float
    error: str | None

    def __init__(self, chunk_name: str, report: str = "", file_count: int = 0,
                 char_count: int = 0, duration_s: float = 0, error: str | None = None):
        self.chunk_name = chunk_name
        self.report = report
        self.file_count = file_count
        self.char_count = char_count
        self.duration_s = duration_s
        self.error = error


def _scan_chunk(
    chunk_name: str,
    chunk_tree: dict[str, Any],
    model: str,
    sub_model: str | None,
    max_tokens: int,
    max_iterations: int,
    verbose: bool,
    reasoning_effort: str | None,
) -> ChunkReport:
    """Scan a single chunk with an RLM instance. Designed to run in a thread."""
    file_count = _tree_file_count(chunk_tree)
    char_count = _tree_size(chunk_tree)

    print(f"  [{chunk_name}] Starting scan ({file_count} files, {char_count:,} chars)")
    start = time.time()

    try:
        lm_kwargs = {}
        if reasoning_effort:
            lm_kwargs["reasoning_effort"] = reasoning_effort

        lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
        sub_lm = dspy.LM(sub_model, max_tokens=max_tokens, **lm_kwargs) if sub_model else lm

        scanner = dspy.RLM(
            CodeScanner,
            max_iterations=max_iterations,
            sub_lm=sub_lm,
            verbose=verbose,
        )

        result = scanner(source_tree=chunk_tree)
        duration = time.time() - start

        print(f"  [{chunk_name}] Done in {duration:.0f}s")
        return ChunkReport(
            chunk_name=chunk_name,
            report=result.documentation,
            file_count=file_count,
            char_count=char_count,
            duration_s=duration,
        )
    except Exception as e:
        duration = time.time() - start
        print(f"  [{chunk_name}] FAILED after {duration:.0f}s: {e}", file=sys.stderr)
        return ChunkReport(
            chunk_name=chunk_name,
            file_count=file_count,
            char_count=char_count,
            duration_s=duration,
            error=str(e),
        )


def scan_chunks_parallel(
    chunks: list[tuple[str, dict[str, Any]]],
    model: str,
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 25,
    max_workers: int = 3,
    verbose: bool = False,
    reasoning_effort: str | None = None,
) -> list[ChunkReport]:
    """Run RLM scans on multiple chunks concurrently.

    Args:
        chunks: List of (chunk_name, subtree) from chunk_source_tree().
        max_workers: Maximum concurrent RLM scans. Each spawns a Deno process,
                     so keep this reasonable (2-4).
    """
    reports: list[ChunkReport] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _scan_chunk,
                name, tree, model, sub_model,
                max_tokens, max_iterations, verbose, reasoning_effort,
            ): name
            for name, tree in chunks
        }

        for future in as_completed(futures):
            chunk_name = futures[future]
            try:
                report = future.result()
                reports.append(report)
            except Exception as e:
                print(f"  [{chunk_name}] Executor error: {e}", file=sys.stderr)
                reports.append(ChunkReport(chunk_name=chunk_name, error=str(e)))

    return reports


# ---------------------------------------------------------------------------
# Report synthesis
# ---------------------------------------------------------------------------

class ReportSynthesizer(dspy.Signature):
    """You are a senior application security engineer. Synthesize multiple
    chunk-level security audit reports into a single unified report.

    Deduplicate findings that appear in multiple chunks. Preserve all unique
    vulnerabilities. Organize by severity (Critical > High > Medium > Low).
    Include a summary table. Reference specific file paths and code patterns."""

    chunk_reports: str = dspy.InputField(
        desc="JSON array of per-chunk security audit reports with chunk names"
    )
    project_name: str = dspy.InputField(
        desc="Name of the project being audited"
    )
    documentation: str = dspy.OutputField(
        desc="Unified, deduplicated security audit report in markdown format"
    )


def synthesize_reports(
    chunk_reports: list[ChunkReport],
    project_name: str,
    model: str,
    max_tokens: int = 16000,
    reasoning_effort: str | None = None,
) -> str:
    """Merge per-chunk reports into a single deduplicated report.

    Uses a standard dspy.ChainOfThought (not RLM) since the input is
    structured text, not a large variable to explore.
    """
    # Build the input: JSON array of chunk reports
    reports_data = []
    for cr in chunk_reports:
        if cr.error:
            reports_data.append({
                "chunk": cr.chunk_name,
                "status": "error",
                "error": cr.error,
            })
        else:
            reports_data.append({
                "chunk": cr.chunk_name,
                "files_scanned": cr.file_count,
                "report": cr.report,
            })

    reports_json = json.dumps(reports_data, indent=2)

    lm_kwargs = {}
    if reasoning_effort:
        lm_kwargs["reasoning_effort"] = reasoning_effort

    lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
    dspy.configure(lm=lm)

    synthesizer = dspy.ChainOfThought(ReportSynthesizer)
    result = synthesizer(chunk_reports=reports_json, project_name=project_name)
    return result.documentation


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_parallel_audit(
    source_path: str | Path,
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 25,
    max_workers: int = 3,
    verbose: bool = False,
    reasoning_effort: str | None = None,
    max_chunk_chars: int = MAX_CHUNK_CHARS,
    project_name: str | None = None,
) -> str:
    """Run a parallelized security audit on a large codebase.

    1. Loads the full source tree
    2. Chunks it into digestible pieces
    3. Scans chunks in parallel with separate RLM instances
    4. Synthesizes findings into a unified report

    Args:
        source_path: Path to the codebase root directory.
        model: Primary LM model identifier.
        sub_model: Model for recursive sub-queries.
        max_tokens: Max tokens per LM call.
        max_iterations: Max REPL iterations per chunk scan.
        max_workers: Max concurrent RLM scans.
        verbose: Enable detailed RLM logging.
        reasoning_effort: Reasoning effort for supported models.
        max_chunk_chars: Max characters per chunk before splitting.
        project_name: Name for the report header (auto-detected if None).

    Returns:
        Markdown-formatted unified security audit report.
    """
    _configure_deno_tls()

    source_path = Path(source_path).resolve()
    if not project_name:
        project_name = source_path.name

    # Phase 1: Load
    print(f"Loading source tree from {source_path} ...")
    full_tree = load_source_tree(source_path)
    if not full_tree:
        raise ValueError(f"No scannable source files found in {source_path}")

    for key in ["CONTENT", "LICENSE", "CHANGELOG"]:
        full_tree.pop(key, None)

    total_files = _tree_file_count(full_tree)
    total_chars = _tree_size(full_tree)
    print(f"Loaded {total_files} files ({total_chars:,} chars)")

    # Phase 2: Chunk
    print(f"Chunking source tree (max {max_chunk_chars:,} chars/chunk) ...")
    chunks = chunk_source_tree(full_tree, max_chars=max_chunk_chars)
    print(f"Split into {len(chunks)} chunks:")
    for name, tree in chunks:
        fc = _tree_file_count(tree)
        cc = _tree_size(tree)
        print(f"  {name}: {fc} files, {cc:,} chars")

    # Phase 3: Parallel scan
    if len(chunks) == 1:
        # Single chunk -- no need for synthesis overhead
        print(f"\nSingle chunk, running direct scan ...")
        lm_kwargs = {}
        if reasoning_effort:
            lm_kwargs["reasoning_effort"] = reasoning_effort
        lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
        sub_lm = dspy.LM(sub_model, max_tokens=max_tokens, **lm_kwargs) if sub_model else lm
        dspy.configure(lm=lm)

        scanner = dspy.RLM(
            CodeScanner,
            max_iterations=max_iterations,
            sub_lm=sub_lm,
            verbose=verbose,
        )
        result = scanner(source_tree=chunks[0][1])
        return result.documentation

    print(f"\nScanning {len(chunks)} chunks in parallel (max {max_workers} workers) ...")
    # Configure the global LM before spawning threads
    lm_kwargs = {}
    if reasoning_effort:
        lm_kwargs["reasoning_effort"] = reasoning_effort
    lm = dspy.LM(model, max_tokens=max_tokens, **lm_kwargs)
    dspy.configure(lm=lm)

    chunk_reports = scan_chunks_parallel(
        chunks=chunks,
        model=model,
        sub_model=sub_model,
        max_tokens=max_tokens,
        max_iterations=max_iterations,
        max_workers=max_workers,
        verbose=verbose,
        reasoning_effort=reasoning_effort,
    )

    successful = [r for r in chunk_reports if not r.error]
    failed = [r for r in chunk_reports if r.error]
    print(f"\nChunk scans complete: {len(successful)} succeeded, {len(failed)} failed")
    total_scan_time = sum(r.duration_s for r in chunk_reports)
    print(f"Total scan time: {total_scan_time:.0f}s (wall clock is less due to parallelism)")

    if not successful:
        raise RuntimeError("All chunk scans failed")

    # Phase 4: Synthesize
    print(f"\nSynthesizing {len(successful)} chunk reports into unified report ...")
    report = synthesize_reports(
        chunk_reports=successful,
        project_name=project_name,
        model=model,
        max_tokens=max_tokens,
        reasoning_effort=reasoning_effort,
    )

    return report
