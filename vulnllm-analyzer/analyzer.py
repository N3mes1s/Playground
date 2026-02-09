"""
Main analyzer: orchestrates repo fetching, language detection, and
vulnerability analysis via the Modal GPU service.

Can be used as a CLI tool or imported as a library.

Usage:
    # Analyze a GitHub repo (requires Modal service deployed):
    python analyzer.py https://github.com/owner/repo

    # Analyze with a specific language filter:
    python analyzer.py https://github.com/owner/repo --languages python java

    # Limit number of files:
    python analyzer.py https://github.com/owner/repo --max-files 50

    # Use local mode (no Modal, uses HuggingFace transformers directly -- slow, needs GPU):
    python analyzer.py https://github.com/owner/repo --local

    # Output JSON report:
    python analyzer.py https://github.com/owner/repo --output report.json
"""

import argparse
import json
import sys
import time
from dataclasses import dataclass, field, asdict

from repo_fetcher import fetch_repo, RepoInfo, PRIMARY_LANGUAGES


@dataclass
class FileResult:
    filename: str
    language: str
    verdict: str
    analysis: str


@dataclass
class AnalysisReport:
    repo_url: str
    repo_name: str
    detected_languages: dict[str, int]
    files_analyzed: int
    files_skipped: int
    total_files_found: int
    results: list[FileResult] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    elapsed_seconds: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def print_summary(self):
        print(f"\n{'=' * 70}")
        print(f"  VulnLLM-R Analysis Report: {self.repo_name}")
        print(f"{'=' * 70}")
        print(f"  Repository:   {self.repo_url}")
        print(f"  Languages:    {', '.join(f'{k} ({v} files)' for k, v in self.detected_languages.items())}")
        print(f"  Analyzed:     {self.files_analyzed} files ({self.files_skipped} skipped)")
        print(f"  Duration:     {self.elapsed_seconds:.1f}s")
        print()

        vuln = self.summary.get("VULNERABLE", 0)
        safe = self.summary.get("NOT VULNERABLE", 0)
        uncertain = self.summary.get("UNCERTAIN", 0)

        print(f"  VULNERABLE:       {vuln}")
        print(f"  NOT VULNERABLE:   {safe}")
        print(f"  UNCERTAIN:        {uncertain}")
        print(f"{'=' * 70}")

        if vuln > 0:
            print(f"\n  Vulnerable files:")
            for r in self.results:
                if r.verdict == "VULNERABLE":
                    print(f"    - {r.filename} ({r.language})")
            print()

        for r in self.results:
            if r.verdict == "VULNERABLE":
                print(f"\n{'─' * 70}")
                print(f"  {r.filename} ({r.language}) -- {r.verdict}")
                print(f"{'─' * 70}")
                # Print first ~40 lines of analysis to keep output manageable
                lines = r.analysis.strip().split("\n")
                for line in lines[:40]:
                    print(f"  {line}")
                if len(lines) > 40:
                    print(f"  ... ({len(lines) - 40} more lines, see full report)")
                print()


def analyze_with_modal(repo_info: RepoInfo, batch_size: int = 8) -> list[FileResult]:
    """Send files to the Modal GPU service for analysis."""
    import modal

    VulnLLMModel = modal.Cls.from_name("vulnllm-analyzer", "VulnLLMModel")
    model = VulnLLMModel()

    results: list[FileResult] = []
    files = repo_info.files

    # Process in batches
    for i in range(0, len(files), batch_size):
        batch = files[i : i + batch_size]
        items = [
            {"code": f.content, "language": f.language, "filename": f.path}
            for f in batch
        ]

        print(f"  Analyzing batch {i // batch_size + 1}/{(len(files) + batch_size - 1) // batch_size} "
              f"({len(items)} files)...")

        batch_results = model.analyze_batch.remote(items)
        for r in batch_results:
            results.append(FileResult(
                filename=r["filename"],
                language=r["language"],
                verdict=r["verdict"],
                analysis=r["analysis"],
            ))

    return results


def analyze_local(repo_info: RepoInfo) -> list[FileResult]:
    """Run analysis locally using HuggingFace transformers (needs GPU)."""
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer

    model_name = "UCSB-SURFI/VulnLLM-R-7B"
    print(f"  Loading model {model_name} locally...")

    tokenizer = AutoTokenizer.from_pretrained(model_name)
    model = AutoModelForCausalLM.from_pretrained(
        model_name,
        torch_dtype=torch.bfloat16,
        device_map="auto",
    )

    system_prompt = (
        "You are VulnLLM-R, an advanced vulnerability detection model specialized in "
        "analyzing source code for security vulnerabilities. Analyze the provided code "
        "step-by-step using chain-of-thought reasoning. Provide a clear verdict: "
        "VULNERABLE or NOT VULNERABLE."
    )

    results: list[FileResult] = []
    for i, f in enumerate(repo_info.files):
        print(f"  [{i + 1}/{len(repo_info.files)}] Analyzing {f.path}...")

        user_prompt = (
            f"Analyze the following {f.language} code from file `{f.path}` "
            f"for security vulnerabilities.\n\nCode:\n```{f.language}\n{f.content}\n```\n\n"
            "Provide your step-by-step reasoning followed by your final verdict."
        )

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        text = tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
        model_inputs = tokenizer([text], return_tensors="pt").to(model.device)

        generated_ids = model.generate(
            model_inputs.input_ids,
            max_new_tokens=4096,
            temperature=0.1,
            top_p=0.95,
        )
        generated_ids = [
            output_ids[len(input_ids):]
            for input_ids, output_ids in zip(model_inputs.input_ids, generated_ids)
        ]
        response = tokenizer.batch_decode(generated_ids, skip_special_tokens=True)[0]

        text_lower = response.lower()
        if "vulnerable" in text_lower and "not vulnerable" not in text_lower:
            verdict = "VULNERABLE"
        elif "not vulnerable" in text_lower:
            verdict = "NOT VULNERABLE"
        else:
            verdict = "UNCERTAIN"

        results.append(FileResult(
            filename=f.path,
            language=f.language,
            verdict=verdict,
            analysis=response,
        ))

    return results


def run_analysis(
    repo_url: str,
    languages: set[str] | None = None,
    max_files: int = 200,
    local: bool = False,
    batch_size: int = 8,
) -> AnalysisReport:
    """
    Full analysis pipeline: fetch repo -> detect langs -> analyze with VulnLLM-R.

    Args:
        repo_url: GitHub repository URL.
        languages: Restrict to these languages. None = auto-detect all.
        max_files: Max files to analyze.
        local: If True, use local HuggingFace inference instead of Modal.
        batch_size: Batch size for Modal inference.

    Returns:
        AnalysisReport with all results.
    """
    start = time.time()

    print(f"\n  Fetching repository: {repo_url}")
    repo_info = fetch_repo(repo_url, languages, max_files)

    print(f"  Repository: {repo_info.name}")
    print(f"  Detected languages: {repo_info.languages}")
    print(f"  Files to analyze: {len(repo_info.files)} "
          f"(found {repo_info.total_files_found}, skipped {repo_info.skipped_files})")

    if not repo_info.files:
        print("  No analyzable files found.")
        return AnalysisReport(
            repo_url=repo_url,
            repo_name=repo_info.name,
            detected_languages=repo_info.languages,
            files_analyzed=0,
            files_skipped=repo_info.skipped_files,
            total_files_found=repo_info.total_files_found,
            elapsed_seconds=time.time() - start,
        )

    print(f"\n  Running vulnerability analysis {'(local)' if local else '(Modal GPU)'}...")

    if local:
        results = analyze_local(repo_info)
    else:
        results = analyze_with_modal(repo_info, batch_size)

    # Build summary
    summary: dict[str, int] = {}
    for r in results:
        summary[r.verdict] = summary.get(r.verdict, 0) + 1

    elapsed = time.time() - start

    return AnalysisReport(
        repo_url=repo_url,
        repo_name=repo_info.name,
        detected_languages=repo_info.languages,
        files_analyzed=len(results),
        files_skipped=repo_info.skipped_files,
        total_files_found=repo_info.total_files_found,
        results=results,
        summary=summary,
        elapsed_seconds=elapsed,
    )


def main():
    parser = argparse.ArgumentParser(
        description="VulnLLM-R: Analyze a GitHub repository for security vulnerabilities",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("repo_url", help="GitHub repository URL to analyze")
    parser.add_argument(
        "--languages", "-l",
        nargs="+",
        default=None,
        help="Languages to analyze (default: auto-detect). Choices: c, cpp, python, java, javascript, etc.",
    )
    parser.add_argument(
        "--max-files", "-m",
        type=int,
        default=200,
        help="Maximum number of files to analyze (default: 200)",
    )
    parser.add_argument(
        "--batch-size", "-b",
        type=int,
        default=8,
        help="Batch size for Modal inference (default: 8)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Use local HuggingFace inference instead of Modal (needs GPU)",
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Write JSON report to this file",
    )

    args = parser.parse_args()

    langs = set(args.languages) if args.languages else None

    report = run_analysis(
        repo_url=args.repo_url,
        languages=langs,
        max_files=args.max_files,
        local=args.local,
        batch_size=args.batch_size,
    )

    report.print_summary()

    if args.output:
        with open(args.output, "w") as f:
            f.write(report.to_json())
        print(f"\n  Full report saved to: {args.output}")


if __name__ == "__main__":
    main()
