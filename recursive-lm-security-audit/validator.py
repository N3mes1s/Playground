"""
Adversarial Finding Validator

Takes raw security findings from the scanner and subjects each one to
a devil's advocate analysis: argues FOR the vulnerability, then argues
AGAINST it (is this just the feature working as designed?), then decides.

This is the "but isn't the test button supposed to do exactly that?" pass.

Pipeline: scan → extract findings → validate each → rebuild report
"""

import json
import re
from typing import Any

import dspy

from scanner import load_source_tree, _configure_deno_tls


# ---------------------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------------------

class FindingExtractor(dspy.Signature):
    """Extract individual security findings from a raw audit report.

    Parse the markdown report and return each finding as a structured JSON
    array. Each finding should have: id, title, severity, description,
    affected_files (list of file paths mentioned), and the original text."""

    raw_report: str = dspy.InputField(
        desc="Raw markdown security audit report from the scanner"
    )
    findings_json: str = dspy.OutputField(
        desc="JSON array of extracted findings, each with: id, title, severity, description, affected_files, original_text"
    )


class FindingValidator(dspy.Signature):
    """You are a senior security engineer doing a second review of a
    vulnerability finding. Your job is to be the devil's advocate.

    For each finding, you must:

    1. PROSECUTION: Argue why this IS a real, exploitable vulnerability.
       - What is the concrete attack scenario?
       - What does the attacker gain that they don't already have?
       - What is the actual impact?

    2. DEFENSE: Argue why this is NOT a vulnerability.
       - Is this behavior required for the feature to work correctly?
       - Does the user already have equivalent access through normal usage?
       - Would "fixing" this break the feature or just add security theater?
       - Is the "attacker" someone who already has legitimate access to do
         the same thing through other means?

    3. VERDICT: Based on both arguments, decide:
       - CONFIRMED: Real vulnerability with concrete exploit path
       - DOWNGRADED: Real concern but lower severity than claimed
       - DISMISSED: Not a vulnerability — feature working as designed,
         or attacker gains nothing they don't already have

    Be ruthlessly honest. Most scanners produce 50%+ false positives.
    The goal is to find the findings that actually matter."""

    finding: str = dspy.InputField(
        desc="The security finding to validate (title, description, severity, affected files)"
    )
    source_code: dict = dspy.InputField(
        desc="Relevant source code files as a dict for the validator to examine"
    )
    prosecution: str = dspy.OutputField(
        desc="Argument for why this IS a real vulnerability with concrete exploit scenario"
    )
    defense: str = dspy.OutputField(
        desc="Devil's advocate argument for why this is NOT a vulnerability or is by-design behavior"
    )
    verdict: str = dspy.OutputField(
        desc="CONFIRMED, DOWNGRADED, or DISMISSED — with a one-paragraph justification"
    )
    true_severity: str = dspy.OutputField(
        desc="Reassessed severity: critical, high, medium, low, or informational"
    )


class ValidatedReportBuilder(dspy.Signature):
    """Build a final security audit report from validated findings.

    Only include CONFIRMED and DOWNGRADED findings. For each finding,
    include the prosecution argument (why it matters) and note any
    caveats from the defense. Group dismissed findings in a brief
    appendix explaining why they were rejected.

    The report should be honest and useful — a developer reading it
    should trust that every finding listed is real and actionable."""

    validated_findings: str = dspy.InputField(
        desc="JSON array of validated findings with verdicts, arguments, and reassessed severity"
    )
    project_name: str = dspy.InputField(
        desc="Name of the project that was audited"
    )
    documentation: str = dspy.OutputField(
        desc="Final validated security audit report in markdown"
    )


# ---------------------------------------------------------------------------
# Core validation logic
# ---------------------------------------------------------------------------

def extract_findings(raw_report: str, model: str, max_tokens: int = 16000) -> list[dict]:
    """Parse a raw audit report into individual structured findings."""
    lm = dspy.LM(model, max_tokens=max_tokens)
    dspy.configure(lm=lm)

    extractor = dspy.ChainOfThought(FindingExtractor)
    result = extractor(raw_report=raw_report)

    try:
        findings = json.loads(result.findings_json)
        if not isinstance(findings, list):
            findings = [findings]
        return findings
    except json.JSONDecodeError:
        # Try to extract JSON from markdown code blocks
        match = re.search(r'```(?:json)?\s*(\[.*?\])\s*```', result.findings_json, re.DOTALL)
        if match:
            return json.loads(match.group(1))
        raise ValueError(f"Could not parse findings JSON from extractor output")


def _collect_relevant_files(
    full_tree: dict[str, Any],
    file_paths: list[str],
    max_chars: int = 500_000,
) -> dict[str, Any]:
    """Extract a subset of the source tree containing only the files
    relevant to a finding. Keeps directory structure intact."""

    def _normalize(p: str) -> list[str]:
        """Turn a path string into a list of segments."""
        # Strip leading ./ or / and split
        p = p.strip().lstrip("./")
        return [s for s in p.split("/") if s]

    def _get_path(tree: dict, segments: list[str]) -> str | None:
        """Walk the tree to find a file by path segments."""
        current = tree
        for seg in segments[:-1]:
            if isinstance(current, dict) and seg in current:
                current = current[seg]
            else:
                return None
        if isinstance(current, dict) and segments[-1] in current:
            val = current[segments[-1]]
            return val if isinstance(val, str) else None
        return None

    def _set_path(tree: dict, segments: list[str], content: str) -> None:
        """Set a value in a nested dict by path segments, creating dicts as needed."""
        current = tree
        for seg in segments[:-1]:
            if seg not in current:
                current[seg] = {}
            current = current[seg]
        current[segments[-1]] = content

    subset: dict[str, Any] = {}
    total_chars = 0

    for path in file_paths:
        segments = _normalize(path)
        if not segments:
            continue
        content = _get_path(full_tree, segments)
        if content and total_chars + len(content) <= max_chars:
            _set_path(subset, segments, content)
            total_chars += len(content)

    return subset


def validate_finding(
    finding: dict,
    source_tree: dict[str, Any],
    model: str,
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 20,
    verbose: bool = False,
) -> dict:
    """Run adversarial validation on a single finding using RLM.

    The RLM gets the finding description and the relevant source code,
    then argues both sides before reaching a verdict.
    """
    # Build the finding text for the validator
    finding_text = json.dumps(finding, indent=2)

    # Collect relevant source files
    affected = finding.get("affected_files", [])
    relevant_code = _collect_relevant_files(source_tree, affected)

    # If we couldn't find any of the referenced files, include a broader context
    if not relevant_code:
        # Give it the first 200k chars of the full tree as fallback
        relevant_code = source_tree

    lm = dspy.LM(model, max_tokens=max_tokens)
    sub_lm = dspy.LM(sub_model, max_tokens=max_tokens) if sub_model else lm
    dspy.configure(lm=lm)

    validator = dspy.RLM(
        FindingValidator,
        max_iterations=max_iterations,
        sub_lm=sub_lm,
        verbose=verbose,
    )

    result = validator(finding=finding_text, source_code=relevant_code)

    return {
        **finding,
        "prosecution": result.prosecution,
        "defense": result.defense,
        "verdict": result.verdict,
        "true_severity": result.true_severity,
    }


def build_validated_report(
    validated_findings: list[dict],
    project_name: str,
    model: str,
    max_tokens: int = 16000,
) -> str:
    """Assemble the final report from validated findings."""
    lm = dspy.LM(model, max_tokens=max_tokens)
    dspy.configure(lm=lm)

    builder = dspy.ChainOfThought(ValidatedReportBuilder)
    result = builder(
        validated_findings=json.dumps(validated_findings, indent=2),
        project_name=project_name,
    )
    return result.documentation


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def validate_report(
    raw_report: str,
    source_path: str,
    model: str = "openrouter/moonshotai/kimi-k2.5",
    sub_model: str | None = None,
    max_tokens: int = 16000,
    max_iterations: int = 20,
    verbose: bool = True,
    project_name: str | None = None,
) -> str:
    """Full validation pipeline: extract → validate each → rebuild report.

    Args:
        raw_report: The raw markdown report from the scanner.
        source_path: Path to the source code (for the validator to read).
        model: LM for validation.
        sub_model: Sub-LM for recursive calls within validation.
        max_tokens: Max tokens per LM call.
        max_iterations: Max RLM iterations per finding validation.
        verbose: Enable detailed logging.
        project_name: Project name for the report header.

    Returns:
        Validated markdown report with only real findings.
    """
    from pathlib import Path

    _configure_deno_tls()

    source_path = Path(source_path).resolve()
    if not project_name:
        project_name = source_path.name

    # Phase 1: Extract individual findings
    print(f"[validate] Extracting findings from raw report ...")
    findings = extract_findings(raw_report, model, max_tokens)
    print(f"[validate] Found {len(findings)} findings to validate")

    # Phase 2: Load source for validation
    print(f"[validate] Loading source tree from {source_path} ...")
    full_tree = load_source_tree(source_path)

    # Phase 3: Validate each finding
    validated = []
    for i, finding in enumerate(findings):
        title = finding.get("title", finding.get("id", f"Finding {i+1}"))
        severity = finding.get("severity", "unknown")
        print(f"\n[validate] ({i+1}/{len(findings)}) Validating: {title} [{severity}]")

        result = validate_finding(
            finding=finding,
            source_tree=full_tree,
            model=model,
            sub_model=sub_model,
            max_tokens=max_tokens,
            max_iterations=max_iterations,
            verbose=verbose,
        )

        verdict = result.get("verdict", "").upper()
        true_sev = result.get("true_severity", "unknown")

        # Parse verdict keyword from the text
        if "CONFIRMED" in verdict:
            status = "CONFIRMED"
        elif "DOWNGRADED" in verdict:
            status = "DOWNGRADED"
        elif "DISMISSED" in verdict:
            status = "DISMISSED"
        else:
            status = "UNKNOWN"

        result["verdict_status"] = status
        validated.append(result)

        print(f"[validate]   → {status} (true severity: {true_sev})")

    # Stats
    confirmed = sum(1 for v in validated if v["verdict_status"] == "CONFIRMED")
    downgraded = sum(1 for v in validated if v["verdict_status"] == "DOWNGRADED")
    dismissed = sum(1 for v in validated if v["verdict_status"] == "DISMISSED")
    print(f"\n[validate] Results: {confirmed} confirmed, {downgraded} downgraded, {dismissed} dismissed")

    # Phase 4: Build final report
    print(f"[validate] Building validated report ...")
    report = build_validated_report(validated, project_name, model, max_tokens)

    return report
