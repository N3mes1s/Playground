"""adversarial-security-sim: stress-test reported findings via attacker/defender debate.

Usage:
    python adversarial-security-sim/cli.py <path-to-audit.md> [--top N] [--rounds K] [--out FILE]

Pipeline:
1. Parse findings out of an existing markdown audit report (e.g. the ones
   already in playground's recursive-lm-security-audit/).
2. For each top finding: set up Attacker vs. Defender, run K debate rounds.
3. Judge agent verdicts each finding: REAL / FALSE_POSITIVE / NEEDS_VALIDATION
   with reasoning citing the debate.
4. Markdown report dropped under ./reports/.

This bolts onto playground's existing security work: it consumes the static
findings and applies a multi-agent rehearsal to triage them.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mirofish_lab import Agent, Report, debate, load_config
from mirofish_lab.config import verify_model
from mirofish_lab.personas import ATTACKER_DEFENDER_PERSONAS, JUDGE_PERSONA


@dataclass
class Finding:
    title: str
    severity: str
    body: str

    def short(self, n: int = 200) -> str:
        first = self.body.strip().splitlines()
        return " ".join(first)[:n]


_HEADING_RE = re.compile(r"^(#{2,4})\s+(.+?)\s*$")
_SEV_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b", re.IGNORECASE)
_NUMBERED_RE = re.compile(r"^\d+[a-z]?[\.)]\s+|^[A-Z][\w ]+:\s*")


def parse_findings(md: str, *, max_findings: int = 30) -> list[Finding]:
    """Extract findings from a markdown audit. Tolerant of formatting variations.

    Strategy: walk H2/H3/H4 headings; treat any heading whose body contains a
    Severity marker as a finding. Body = text until next heading at same or
    shallower depth.
    """
    lines = md.splitlines()
    headings: list[tuple[int, int, str]] = []  # (line_index, depth, title)
    for i, ln in enumerate(lines):
        m = _HEADING_RE.match(ln)
        if m:
            headings.append((i, len(m.group(1)), m.group(2)))

    findings: list[Finding] = []
    for idx, (line_idx, depth, title) in enumerate(headings):
        end = len(lines)
        for jdx in range(idx + 1, len(headings)):
            n_line, n_depth, _ = headings[jdx]
            if n_depth <= depth:
                end = n_line
                break
        body = "\n".join(lines[line_idx + 1 : end]).strip()

        sev_m = _SEV_RE.search(body[:500])
        if not sev_m:
            continue
        if not _NUMBERED_RE.match(title) and depth > 2:
            # also allow H3/H4 named findings
            pass

        clean_title = re.sub(r"^\d+[a-z]?[\.)]\s*", "", title).strip()
        findings.append(
            Finding(title=clean_title, severity=sev_m.group(1).upper(), body=body)
        )
        if len(findings) >= max_findings:
            break
    return findings


def run(report_path: Path, *, top: int, rounds: int, out_path: Path) -> Path:
    cfg = load_config()
    print(f"[config] model={cfg.model}", file=sys.stderr)
    verify_model(cfg)

    md = report_path.read_text()
    findings = parse_findings(md)
    print(f"[parse] extracted {len(findings)} findings from {report_path}", file=sys.stderr)
    findings = findings[:top]

    out = Report(
        title=f"Adversarial Security Sim — {report_path.name}",
        meta={
            "Source": str(report_path),
            "Findings analysed": str(len(findings)),
            "Rounds": str(rounds),
            "Model": cfg.model,
        },
    )

    judge = Agent(JUDGE_PERSONA, cfg)

    for i, f in enumerate(findings, 1):
        print(f"[finding {i}/{len(findings)}] {f.severity}: {f.title}", file=sys.stderr)
        # Fresh attacker/defender per finding for clean memory.
        atk_p, def_p = ATTACKER_DEFENDER_PERSONAS
        attacker = Agent(atk_p, cfg)
        defender = Agent(def_p, cfg)

        seed = (
            f"# Reported finding\n\n"
            f"**Title**: {f.title}\n\n"
            f"**Severity claimed**: {f.severity}\n\n"
            f"**Report body**:\n\n{f.body}\n\n"
            f"As the Attacker, propose a concrete exploit chain. Cite specific code "
            f"references. If you cannot construct a plausible exploit from the "
            f"information given, say so and explain what would be needed."
        )

        transcript = debate(attacker, defender, seed_prompt=seed, rounds=rounds)
        debate_md = "\n\n".join(f"### {t.speaker}\n\n{t.content}" for t in transcript)

        verdict = judge.respond(
            f"Finding: **{f.title}** ({f.severity})\n\n"
            f"# Debate transcript\n\n{debate_md}\n\n"
            f"Verdict in [REAL, FALSE_POSITIVE, NEEDS_VALIDATION]. "
            f"In 5 lines or fewer: justify, citing the strongest single point from "
            f"each side. If NEEDS_VALIDATION, list the exact one or two checks a "
            f"human should run."
        )
        out.add(f"Finding {i}: {f.title} ({f.severity})", debate_md + "\n\n---\n\n**Verdict**\n\n" + verdict.content)

    written = out.write(out_path)
    print(f"[done] wrote {written}", file=sys.stderr)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run attacker/defender debate over an audit report.")
    parser.add_argument("report", type=Path, help="Path to an existing audit markdown report")
    parser.add_argument("--top", type=int, default=5, help="How many findings to debate")
    parser.add_argument("--rounds", type=int, default=2, help="Debate rounds per finding")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    if args.out is None:
        args.out = Path("adversarial-security-sim/reports") / f"{args.report.stem}-adversarial.md"

    run(args.report, top=args.top, rounds=args.rounds, out_path=args.out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
