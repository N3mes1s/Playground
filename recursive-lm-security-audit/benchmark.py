"""
CVE Benchmark Pipeline

End-to-end pipeline that takes a GitHub Security Advisory, clones the
vulnerable repo, scans it, checks if the CVE was found, and if not,
analyzes the gap and autonomously improves the scanner.

Usage:
    python benchmark.py GHSA-4jqp-9qjv-57m2
    python benchmark.py CVE-2026-1709
    python benchmark.py --batch advisories.txt
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

import dspy

from scanner import load_source_tree, _configure_deno_tls, CodeScanner, SOURCE_EXTENSIONS


# ---------------------------------------------------------------------------
# Advisory fetching
# ---------------------------------------------------------------------------

@dataclass
class Advisory:
    """Parsed GitHub Security Advisory."""
    ghsa_id: str = ""
    cve_id: str = ""
    summary: str = ""
    description: str = ""
    severity: str = ""
    cvss_score: float = 0.0
    cwe_ids: list[str] = field(default_factory=list)
    package_ecosystem: str = ""
    package_name: str = ""
    vulnerable_versions: str = ""
    patched_versions: str = ""
    repo_url: str = ""
    affected_files: list[str] = field(default_factory=list)


class AdvisoryFetcher(dspy.Signature):
    """Given a GitHub Security Advisory page content, extract structured
    vulnerability information including the affected repository URL,
    vulnerable version range, and technical details about the vulnerability.

    If the advisory mentions specific files or code paths, extract those too."""

    advisory_text: str = dspy.InputField(
        desc="Raw text content from the GitHub advisory page"
    )
    advisory_json: str = dspy.OutputField(
        desc="JSON object with fields: ghsa_id, cve_id, summary, description, "
             "severity, cvss_score, cwe_ids (list), package_ecosystem, package_name, "
             "vulnerable_versions, patched_versions, repo_url (GitHub URL of the "
             "affected project), affected_files (list of file paths mentioned)"
    )


def fetch_advisory(advisory_id: str, model: str = "openrouter/moonshotai/kimi-k2.5") -> Advisory:
    """Fetch and parse a GitHub Security Advisory by GHSA or CVE ID.

    Uses curl to fetch the advisory page, then an LM to extract structured data.
    """
    # Determine the URL
    if advisory_id.startswith("GHSA-"):
        url = f"https://github.com/advisories/{advisory_id}"
    elif advisory_id.startswith("CVE-"):
        url = f"https://github.com/advisories?query={advisory_id}"
    else:
        raise ValueError(f"Unknown advisory format: {advisory_id}. Use GHSA-xxx or CVE-xxx")

    # Fetch the page
    print(f"[benchmark] Fetching advisory: {url}")
    result = subprocess.run(
        ["curl", "-sL", "--max-time", "30", url],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Failed to fetch advisory: {result.stderr}")

    page_text = result.stdout

    # Strip HTML tags for a rough text extraction
    import html
    text = re.sub(r'<script[^>]*>.*?</script>', '', page_text, flags=re.DOTALL)
    text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL)
    text = re.sub(r'<[^>]+>', ' ', text)
    text = html.unescape(text)
    text = re.sub(r'\s+', ' ', text).strip()

    # Truncate to avoid token limits
    text = text[:15000]

    # Use LM to extract structured info
    lm = dspy.LM(model, max_tokens=4000)
    dspy.configure(lm=lm)

    extractor = dspy.ChainOfThought(AdvisoryFetcher)
    result = extractor(advisory_text=text)

    # Parse JSON
    try:
        data = json.loads(result.advisory_json)
    except json.JSONDecodeError:
        match = re.search(r'```(?:json)?\s*(\{.*?\})\s*```', result.advisory_json, re.DOTALL)
        if match:
            data = json.loads(match.group(1))
        else:
            raise ValueError(f"Could not parse advisory JSON")

    return Advisory(**{k: v for k, v in data.items() if k in Advisory.__dataclass_fields__})


# ---------------------------------------------------------------------------
# Repo cloning at vulnerable version
# ---------------------------------------------------------------------------

def clone_vulnerable_version(advisory: Advisory, target_dir: str) -> Path:
    """Clone the affected repo at the vulnerable version."""
    repo_url = advisory.repo_url
    if not repo_url:
        raise ValueError("Advisory has no repo_url")

    # Try to find the right tag for the vulnerable version
    vuln_ver = advisory.vulnerable_versions or ""
    patched_ver = advisory.patched_versions or ""

    # Strategy: try to clone just before the patched version
    # Parse version hints
    tag_to_try = None
    if patched_ver:
        # Try common tag formats: v1.2.3, 1.2.3
        ver_match = re.search(r'(\d+\.\d+\.\d+)', patched_ver)
        if ver_match:
            ver = ver_match.group(1)
            parts = ver.split(".")
            # Decrement patch version
            parts[-1] = str(max(0, int(parts[-1]) - 1))
            prev_ver = ".".join(parts)
            tag_to_try = [f"v{prev_ver}", prev_ver, f"v{ver}", ver]

    cloned = False
    if tag_to_try:
        for tag in tag_to_try:
            print(f"[benchmark] Trying to clone {repo_url} at tag {tag} ...")
            cmd = ["git", "clone", "--depth", "1", "--branch", tag, repo_url, target_dir]
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                print(f"[benchmark] Cloned at tag {tag}")
                cloned = True
                break
            # Clean up failed clone
            if Path(target_dir).exists():
                shutil.rmtree(target_dir)

    if not cloned:
        print(f"[benchmark] Cloning {repo_url} at HEAD (could not find vulnerable tag)")
        cmd = ["git", "clone", "--depth", "1", repo_url, target_dir]
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"git clone failed: {r.stderr}")

    return Path(target_dir)


# ---------------------------------------------------------------------------
# Scoped scanning (only relevant parts of the repo)
# ---------------------------------------------------------------------------

def scope_source_tree(
    full_tree: dict[str, Any],
    advisory: Advisory,
    max_chars: int = 3_000_000,
) -> dict[str, Any]:
    """Narrow the source tree to code most likely to contain the vulnerability.

    Uses affected_files from the advisory as hints, falling back to the
    full tree if it's small enough.
    """
    from parallel_scanner import _tree_size

    # If the tree is small enough, just use it all
    total = _tree_size(full_tree)
    if total <= max_chars:
        return full_tree

    # Try to find the relevant directories from affected_files
    if advisory.affected_files:
        # Extract directory prefixes
        dirs = set()
        for f in advisory.affected_files:
            parts = f.strip("./").split("/")
            if len(parts) > 1:
                dirs.add(parts[0])
                if len(parts) > 2:
                    dirs.add(f"{parts[0]}/{parts[1]}")

        scoped: dict[str, Any] = {}
        for d in dirs:
            parts = d.split("/")
            current = full_tree
            for p in parts:
                if isinstance(current, dict) and p in current:
                    current = current[p]
                else:
                    current = None
                    break
            if current and isinstance(current, dict):
                # Navigate and add
                node = scoped
                for p in parts[:-1]:
                    node.setdefault(p, {})
                    node = node[p]
                node[parts[-1]] = current

        if scoped and _tree_size(scoped) <= max_chars:
            return scoped

    # Fallback: take the first max_chars worth of content
    # (sorted by directory name for consistency)
    return full_tree


# ---------------------------------------------------------------------------
# CVE matching
# ---------------------------------------------------------------------------

class CVEMatcher(dspy.Signature):
    """You are evaluating whether a security scanner successfully detected a
    known vulnerability (CVE).

    Compare the scanner's report against the known CVE details. Determine:
    1. Was the exact vulnerability found? (exact match)
    2. Was a closely related finding reported that covers the same root cause? (partial match)
    3. Was the vulnerability completely missed? (miss)

    Be strict: a finding about "input validation" doesn't match a specific
    command injection CVE unless it identifies the same code path and attack vector."""

    known_cve: str = dspy.InputField(
        desc="JSON description of the known CVE (id, description, affected files, CWE, root cause)"
    )
    scanner_report: str = dspy.InputField(
        desc="The scanner's security audit report"
    )
    match_result: str = dspy.OutputField(
        desc="EXACT_MATCH, PARTIAL_MATCH, or MISS — with a justification paragraph"
    )
    matched_finding: str = dspy.OutputField(
        desc="If EXACT or PARTIAL match, which finding in the report corresponds to the CVE. If MISS, 'none'."
    )


class GapAnalyzer(dspy.Signature):
    """A known CVE was NOT detected by our security scanner. Analyze why.

    Given the CVE details, the source code, and the scanner's report,
    determine:
    1. What specific vulnerability pattern did the scanner miss?
    2. Why did it miss it? (too complex, wrong focus area, needs domain knowledge, etc.)
    3. What concrete instruction could be added to the scanner's prompt to
       help it catch this class of vulnerability in the future?

    The instruction should be specific and actionable, not vague. For example:
    - BAD: "Look for security issues more carefully"
    - GOOD: "When reviewing TLS/SSL configuration code, check that verify_mode
      is set to CERT_REQUIRED, not CERT_OPTIONAL or CERT_NONE. CERT_OPTIONAL
      on a server that should enforce mTLS is a critical misconfiguration."

    The instruction will be appended to the scanner's system prompt."""

    known_cve: str = dspy.InputField(
        desc="JSON description of the missed CVE"
    )
    scanner_report: str = dspy.InputField(
        desc="What the scanner actually reported"
    )
    source_code: dict = dspy.InputField(
        desc="The source code that was scanned"
    )
    gap_analysis: str = dspy.OutputField(
        desc="Why the scanner missed this vulnerability"
    )
    new_instruction: str = dspy.OutputField(
        desc="A specific, concrete instruction to add to the scanner prompt to catch this pattern in the future"
    )


# ---------------------------------------------------------------------------
# Knowledge base for learned patterns
# ---------------------------------------------------------------------------

PATTERNS_FILE = Path(__file__).parent / "learned_patterns.json"


def load_patterns() -> list[dict]:
    """Load previously learned vulnerability patterns."""
    if PATTERNS_FILE.exists():
        return json.loads(PATTERNS_FILE.read_text())
    return []


_pattern_lock = threading.Lock()


def save_pattern(pattern: dict) -> None:
    """Append a new learned pattern (thread-safe)."""
    with _pattern_lock:
        patterns = load_patterns()
        patterns.append(pattern)
        PATTERNS_FILE.write_text(json.dumps(patterns, indent=2))
    print(f"[benchmark] Saved new pattern to {PATTERNS_FILE} ({len(patterns)} total)")


def get_enhanced_scanner_signature() -> type:
    """Build a CodeScanner signature enhanced with learned patterns."""
    patterns = load_patterns()

    if not patterns:
        return CodeScanner

    # Build extra instructions from learned patterns
    extra = "\n\nAdditionally, pay special attention to these vulnerability patterns " \
            "learned from missed CVEs:\n"
    for i, p in enumerate(patterns, 1):
        instruction = p.get("instruction", "")
        cve = p.get("cve_id", "unknown")
        extra += f"\n{i}. [{cve}] {instruction}"

    # Create an enhanced signature class
    class EnhancedCodeScanner(dspy.Signature):
        __doc__ = CodeScanner.__doc__ + extra

        source_tree: dict = dspy.InputField(
            desc="Dictionary containing folder-to-file mapping of the target codebase"
        )
        documentation: str = dspy.OutputField(
            desc="Detailed security audit report in markdown format"
        )

    return EnhancedCodeScanner


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

@dataclass
class BenchmarkResult:
    """Result of running the benchmark pipeline on a single advisory."""
    advisory: Advisory
    match_status: str = ""  # EXACT_MATCH, PARTIAL_MATCH, MISS
    matched_finding: str = ""
    scanner_report: str = ""
    gap_analysis: str = ""
    new_instruction: str = ""
    scan_duration_s: float = 0
    improved: bool = False


def run_benchmark(
    advisory_id: str,
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 35,
    verbose: bool = True,
    auto_improve: bool = True,
) -> BenchmarkResult:
    """Full pipeline: fetch advisory → clone → scan → match → analyze gap → improve.

    Args:
        advisory_id: GHSA-xxx or CVE-xxx identifier.
        model: LM for scanning and analysis.
        sub_model: Sub-LM for recursive calls.
        max_tokens: Max tokens per call.
        max_iterations: Max RLM iterations.
        verbose: Enable detailed logging.
        auto_improve: If True, automatically add learned patterns on miss.

    Returns:
        BenchmarkResult with match status and any improvements made.
    """
    _configure_deno_tls()

    # Phase 1: Fetch advisory
    print("=" * 70)
    print("PHASE 1: FETCH ADVISORY")
    print("=" * 70)
    advisory = fetch_advisory(advisory_id, model)
    print(f"  CVE:      {advisory.cve_id}")
    print(f"  Summary:  {advisory.summary[:100]}")
    print(f"  Severity: {advisory.severity} (CVSS {advisory.cvss_score})")
    print(f"  Package:  {advisory.package_name} ({advisory.package_ecosystem})")
    print(f"  Repo:     {advisory.repo_url}")
    print(f"  Files:    {advisory.affected_files}")
    print(f"  CWEs:     {advisory.cwe_ids}")

    result = BenchmarkResult(advisory=advisory)

    # Phase 2: Clone vulnerable version
    print("\n" + "=" * 70)
    print("PHASE 2: CLONE VULNERABLE VERSION")
    print("=" * 70)
    tmp_dir = tempfile.mkdtemp(prefix="rlm-benchmark-")
    try:
        source_path = clone_vulnerable_version(advisory, tmp_dir)

        # Phase 3: Load and scope source tree
        print("\n" + "=" * 70)
        print("PHASE 3: SCAN")
        print("=" * 70)
        full_tree = load_source_tree(source_path)
        from parallel_scanner import _tree_size, _tree_file_count
        total_files = _tree_file_count(full_tree)
        total_chars = _tree_size(full_tree)
        print(f"  Full tree: {total_files} files, {total_chars:,} chars")

        scoped_tree = scope_source_tree(full_tree, advisory)
        scoped_files = _tree_file_count(scoped_tree)
        scoped_chars = _tree_size(scoped_tree)
        print(f"  Scoped:    {scoped_files} files, {scoped_chars:,} chars")

        # Use enhanced scanner if we have learned patterns
        ScannerSig = get_enhanced_scanner_signature()
        patterns = load_patterns()
        if patterns:
            print(f"  Using {len(patterns)} learned patterns from previous benchmarks")

        lm = dspy.LM(model, max_tokens=max_tokens)
        sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
        dspy.configure(lm=lm)

        scanner = dspy.RLM(
            ScannerSig,
            max_iterations=max_iterations,
            sub_lm=sub_lm,
            verbose=verbose,
        )

        start = time.time()
        scan_result = scanner(source_tree=scoped_tree)
        result.scan_duration_s = time.time() - start
        result.scanner_report = scan_result.documentation

        print(f"\n  Scan complete in {result.scan_duration_s:.0f}s")
        print(f"  Report length: {len(result.scanner_report)} chars")

        # Phase 4: Match CVE
        print("\n" + "=" * 70)
        print("PHASE 4: CVE MATCHING")
        print("=" * 70)

        cve_desc = json.dumps({
            "cve_id": advisory.cve_id,
            "summary": advisory.summary,
            "description": advisory.description,
            "cwe_ids": advisory.cwe_ids,
            "affected_files": advisory.affected_files,
            "severity": advisory.severity,
        }, indent=2)

        matcher = dspy.ChainOfThought(CVEMatcher)
        match_result = matcher(known_cve=cve_desc, scanner_report=result.scanner_report)

        # Parse match status
        match_text = match_result.match_result.upper()
        if "EXACT" in match_text:
            result.match_status = "EXACT_MATCH"
        elif "PARTIAL" in match_text:
            result.match_status = "PARTIAL_MATCH"
        else:
            result.match_status = "MISS"

        result.matched_finding = match_result.matched_finding

        print(f"  Result: {result.match_status}")
        print(f"  Detail: {match_result.match_result[:200]}")
        if result.matched_finding and result.matched_finding != "none":
            print(f"  Matched: {result.matched_finding[:200]}")

        # Phase 5: Gap analysis + improvement (only on MISS)
        if result.match_status == "MISS" and auto_improve:
            print("\n" + "=" * 70)
            print("PHASE 5: GAP ANALYSIS & IMPROVEMENT")
            print("=" * 70)

            analyzer = dspy.RLM(
                GapAnalyzer,
                max_iterations=max_iterations,
                sub_lm=sub_lm,
                verbose=verbose,
            )

            gap_result = analyzer(
                known_cve=cve_desc,
                scanner_report=result.scanner_report,
                source_code=scoped_tree,
            )

            result.gap_analysis = gap_result.gap_analysis
            result.new_instruction = gap_result.new_instruction

            print(f"\n  Gap analysis: {result.gap_analysis[:300]}")
            print(f"\n  New instruction: {result.new_instruction[:300]}")

            # Save the learned pattern
            save_pattern({
                "cve_id": advisory.cve_id,
                "ghsa_id": advisory.ghsa_id,
                "summary": advisory.summary,
                "cwe_ids": advisory.cwe_ids,
                "gap_analysis": result.gap_analysis,
                "instruction": result.new_instruction,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            })
            result.improved = True
            print(f"\n  Pattern saved. Scanner will use it on future scans.")

        elif result.match_status == "MISS":
            print("\n  [skip] Auto-improve disabled. Use --auto-improve to enable.")

    finally:
        if Path(tmp_dir).exists():
            shutil.rmtree(tmp_dir, ignore_errors=True)

    # Summary
    print("\n" + "=" * 70)
    print("BENCHMARK RESULT")
    print("=" * 70)
    status_emoji = {"EXACT_MATCH": "PASS", "PARTIAL_MATCH": "PARTIAL", "MISS": "FAIL"}
    print(f"  {status_emoji.get(result.match_status, '???')} | {advisory.cve_id} | {advisory.summary[:60]}")
    if result.improved:
        print(f"  Scanner improved with new pattern for future scans")

    return result


def run_batch_benchmark(
    advisory_ids: list[str],
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 35,
    verbose: bool = False,
    auto_improve: bool = True,
) -> list[BenchmarkResult]:
    """Run the benchmark pipeline on multiple advisories sequentially.

    Each miss improves the scanner, so order matters -- later scans benefit
    from patterns learned from earlier misses.
    """
    results = []
    for i, aid in enumerate(advisory_ids):
        print(f"\n{'#' * 70}")
        print(f"# BENCHMARK {i+1}/{len(advisory_ids)}: {aid}")
        print(f"{'#' * 70}\n")

        try:
            result = run_benchmark(
                advisory_id=aid,
                model=model,
                sub_model=sub_model,
                max_tokens=max_tokens,
                max_iterations=max_iterations,
                verbose=verbose,
                auto_improve=auto_improve,
            )
            results.append(result)
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append(BenchmarkResult(
                advisory=Advisory(ghsa_id=aid),
                match_status="ERROR",
            ))

    # Final summary
    print(f"\n{'=' * 70}")
    print("BATCH BENCHMARK SUMMARY")
    print(f"{'=' * 70}")
    exact = sum(1 for r in results if r.match_status == "EXACT_MATCH")
    partial = sum(1 for r in results if r.match_status == "PARTIAL_MATCH")
    missed = sum(1 for r in results if r.match_status == "MISS")
    errors = sum(1 for r in results if r.match_status == "ERROR")
    improved = sum(1 for r in results if r.improved)

    print(f"  Total:    {len(results)}")
    print(f"  Exact:    {exact}")
    print(f"  Partial:  {partial}")
    print(f"  Missed:   {missed}")
    print(f"  Errors:   {errors}")
    print(f"  Improved: {improved} new patterns learned")

    patterns = load_patterns()
    print(f"  Knowledge base: {len(patterns)} patterns total")

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="CVE Benchmark Pipeline - Test scanner against known vulnerabilities",
    )
    parser.add_argument(
        "advisories",
        nargs="*",
        help="GHSA-xxx or CVE-xxx identifiers to benchmark against",
    )
    parser.add_argument(
        "--batch",
        default=None,
        help="File with one advisory ID per line",
    )
    parser.add_argument(
        "--model",
        default="openrouter/moonshotai/kimi-k2.5",
        help="LM model for scanning and analysis",
    )
    parser.add_argument(
        "--sub-model",
        default=None,
        help="Sub-model for recursive calls",
    )
    parser.add_argument(
        "--max-tokens",
        type=int,
        default=16000,
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=35,
    )
    parser.add_argument(
        "--no-improve",
        action="store_true",
        help="Don't auto-improve the scanner on misses",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
    )
    parser.add_argument(
        "-o", "--output",
        default=None,
        help="Write results JSON to file",
    )
    parser.add_argument(
        "--show-patterns",
        action="store_true",
        help="Show all learned patterns and exit",
    )
    parser.add_argument(
        "--reset-patterns",
        action="store_true",
        help="Clear all learned patterns and exit",
    )

    args = parser.parse_args()

    if args.show_patterns:
        patterns = load_patterns()
        if not patterns:
            print("No learned patterns yet.")
        else:
            print(f"{len(patterns)} learned patterns:\n")
            for p in patterns:
                print(f"  [{p.get('cve_id', '?')}] {p.get('instruction', '?')[:100]}")
        return

    if args.reset_patterns:
        if PATTERNS_FILE.exists():
            PATTERNS_FILE.unlink()
            print("Patterns cleared.")
        else:
            print("No patterns file to clear.")
        return

    # Collect advisory IDs
    ids = list(args.advisories)
    if args.batch:
        ids.extend(Path(args.batch).read_text().strip().splitlines())
    ids = [i.strip() for i in ids if i.strip()]

    if not ids:
        parser.error("No advisory IDs provided. Use positional args or --batch file.")

    # When writing structured output, redirect all progress to stderr
    if args.output:
        import builtins
        _orig_print = builtins.print
        def _stderr_print(*a, **kw):
            kw.setdefault("file", sys.stderr)
            _orig_print(*a, **kw)
        builtins.print = _stderr_print

    if len(ids) == 1:
        result = run_benchmark(
            advisory_id=ids[0],
            model=args.model,
            sub_model=args.sub_model,
            max_tokens=args.max_tokens,
            max_iterations=args.max_iterations,
            verbose=not args.quiet,
            auto_improve=not args.no_improve,
        )
        results = [result]
    else:
        results = run_batch_benchmark(
            advisory_ids=ids,
            model=args.model,
            sub_model=args.sub_model,
            max_tokens=args.max_tokens,
            max_iterations=args.max_iterations,
            verbose=not args.quiet,
            auto_improve=not args.no_improve,
        )

    if args.output:
        out_data = []
        for r in results:
            d = {
                "advisory": asdict(r.advisory),
                "match_status": r.match_status,
                "matched_finding": r.matched_finding,
                "gap_analysis": r.gap_analysis,
                "new_instruction": r.new_instruction,
                "scan_duration_s": r.scan_duration_s,
                "improved": r.improved,
            }
            out_data.append(d)
        output_json = json.dumps(out_data, indent=2)
        if args.output == "/dev/stdout":
            # Write clean JSON to stdout for batch runner to parse
            sys.stdout.write(output_json)
        else:
            Path(args.output).write_text(output_json)
            print(f"\nResults written to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
