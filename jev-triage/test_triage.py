"""
Offline tests for jev-triage. No API key or network required.

Run with:  python -m pytest test_triage.py   (or)   python test_triage.py
"""

from __future__ import annotations

from findings import Finding, load_findings, load_json_findings
from jev_client import Choice, JevClient, Noul, Score
from triage import build_questions, interpret, triage_all


# --------------------------------------------------------------------------- #
# HTTP response normalization
# --------------------------------------------------------------------------- #


def test_normalize_http_all_types():
    questions = {
        "is_real": Noul(instructions="real?"),
        "sev": Score(instructions="sev", criteria=["Low", "High"]),
        "cat": Choice(instructions="cat", criteria={"a": "x", "b": "y"}),
    }
    payload = {
        "model": "jev-latest",
        "answers": {
            "is_real": {"noul": 0.83},
            "sev": {"score": 1.4, "legend": {"0": "Low", "1": "High"},
                    "probabilities": {"Low": 0.3, "High": 0.7}, "confidence": 0.7},
            "cat": {"choice": "a", "probabilities": {"a": 0.6, "b": 0.4},
                    "confidence": 0.6},
        },
        "usage": {"input_tokens": 100, "output_tokens": 0},
    }
    resp = JevClient.normalize_http(payload, questions)
    assert resp["is_real"].noul == 0.83
    assert resp["sev"].score == 1.4
    assert resp["sev"].probabilities["High"] == 0.7
    assert resp["cat"].choice == "a"
    assert resp.usage["input_tokens"] == 100


# --------------------------------------------------------------------------- #
# Threshold interpretation
# --------------------------------------------------------------------------- #


def _resp(real, reach, sev_probs):
    questions = build_questions()
    payload = {
        "answers": {
            "is_real": {"noul": real},
            "reachable": {"noul": reach},
            "severity": {"score": 3.0, "probabilities": sev_probs, "confidence": 0.6},
            "category": {"choice": "injection", "probabilities": {"injection": 0.8},
                         "confidence": 0.8},
        },
        "usage": {},
    }
    return questions, JevClient.normalize_http(payload, questions)


def test_interpret_keeps_real_reachable():
    f = Finding(id="X", title="t")
    _, resp = _resp(0.9, 0.8, {"High": 0.9, "Critical": 0.1})
    res = interpret(f, resp, is_real_threshold=0.6, reachable_threshold=0.5)
    assert res.keep is True
    assert res.severity_label == "High"


def test_interpret_drops_false_positive():
    f = Finding(id="X", title="t")
    _, resp = _resp(0.2, 0.9, {"Low": 0.8})
    res = interpret(f, resp, is_real_threshold=0.6, reachable_threshold=0.5)
    assert res.keep is False
    assert "is_real" in res.reason


def test_interpret_drops_unreachable():
    f = Finding(id="X", title="t")
    _, resp = _resp(0.9, 0.1, {"High": 0.9})
    res = interpret(f, resp, is_real_threshold=0.6, reachable_threshold=0.5)
    assert res.keep is False
    assert "reachable" in res.reason


# --------------------------------------------------------------------------- #
# Parsing
# --------------------------------------------------------------------------- #


def test_load_json_findings(tmp_path=None):
    findings = load_json_findings("example_findings.json")
    assert len(findings) == 6
    ids = {f.id for f in findings}
    assert "VULN-01" in ids
    assert findings[0].severity == "Critical"


def test_load_markdown_findings():
    md = (
        "# Report\n\n## Critical\n\n"
        "### VULN-01: Something bad\n"
        "**Location**: `a/b.py`\n"
        "**Severity**: Critical\n"
        "**CWE**: CWE-89\n\n"
        "Some description.\n```py\nx = eval(user)\n```\n\n"
        "### Not a finding header\n"
        "ignored.\n"
    )
    import tempfile, os
    p = os.path.join(tempfile.mkdtemp(), "r.md")
    with open(p, "w") as fh:
        fh.write(md)
    findings = load_markdown_findings_path(p)
    assert len(findings) == 1
    assert findings[0].id == "VULN-01"
    assert findings[0].file == "a/b.py"
    assert findings[0].severity == "Critical"
    assert "eval(user)" in findings[0].code


def load_markdown_findings_path(p):
    from findings import load_markdown_findings
    return load_markdown_findings(p)


# --------------------------------------------------------------------------- #
# End-to-end with the stub backend
# --------------------------------------------------------------------------- #


def test_demo_backend_end_to_end():
    from demo_backend import StubJevClient

    findings = load_findings("example_findings.json")
    results = triage_all(StubJevClient(), findings)
    assert len(results) == len(findings)
    by_id = {r.finding.id: r for r in results}
    # The obvious RCE should be kept; the sanitized path-traversal FP should drop.
    assert by_id["VULN-01"].keep is True
    assert by_id["VULN-05"].keep is False


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ok  {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} tests passed")
