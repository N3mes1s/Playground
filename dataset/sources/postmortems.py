"""danluu/post-mortems ingester.

The repo is a curated README of post-mortem links (~500 entries).
We parse the markdown, extract `[title](url)` pairs, classify them
heuristically by tags / categories, and emit our schema. We do NOT
fetch the linked pages by default (each is hosted elsewhere with
its own ToS); the link itself is the ground-truth pointer.

Each entry becomes a `post_mortem` intent: the title becomes the
intent's title, a templated body invites the planner to imagine the
PRE-incident migration / change that led to this post-mortem.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT_DIR = ROOT / "dataset" / "data" / "real"
CLONE_DIR = ROOT / ".clones" / "post-mortems"
REPO_URL = "https://github.com/danluu/post-mortems.git"


# Heuristic tag map: keyword in title/url -> tag
_TAG_HINTS = {
    "aws": "aws", "ec2": "aws", "s3": "aws", "rds": "aws",
    "azure": "azure", "gcp": "gcp", "google": "google",
    "github": "github", "gitlab": "gitlab", "bitbucket": "bitbucket",
    "cloudflare": "cloudflare", "fastly": "fastly",
    "stripe": "stripe", "twilio": "twilio",
    "postgres": "postgres", "mysql": "mysql", "mongodb": "mongodb",
    "redis": "redis", "kafka": "kafka",
    "kubernetes": "k8s", "k8s": "k8s", "docker": "docker",
    "deploy": "deploy", "rollout": "rollout", "rollback": "rollback",
    "migration": "migration", "schema": "schema",
    "outage": "outage", "incident": "incident",
    "dns": "dns", "bgp": "bgp", "tls": "tls",
}


# Post-mortem entries start a line with [Title](url). description...
# Use a category-section parser: track current `## Section` heading so we
# can tag each entry with its section.
_LINK_RE = re.compile(r"^\[([^\]]+)\]\(([^)]+)\)\.?\s*(.*)$", re.MULTILINE)
_HEADING_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)


def _intent_md_for(title: str, url: str, blurb: str, tags: list[str]) -> str:
    return (
        f"# {title}\n\n"
        f"This is a real public post-mortem — "
        f"[{url}]({url})\n\n"
        f"## Pre-incident framing\n\n"
        f"Imagine you are the team running the change that ultimately "
        f"caused this incident. The post-mortem is the OUTCOME you are "
        f"trying to avoid. Your job is to produce a rollout plan that "
        f"would have surfaced the constraint that was violated.\n\n"
        f"### Title from the source post-mortem\n\n{title.strip()}\n\n"
        f"### Brief from the source link\n\n{blurb.strip() or '(none)'}\n\n"
        f"### Tags\n\n{', '.join(tags) or '(none)'}\n\n"
        f"### What to produce\n\nA stakeholder-constrained rollout plan "
        f"for the change THAT WOULD HAVE CAUSED THIS INCIDENT. Identify "
        f"the constraint that, if honoured, would have prevented the "
        f"outage. Reference real specifics from the linked post-mortem "
        f"if you can infer them from the title alone."
    )


def _parse_readme(readme_path: Path) -> list[dict]:
    text = readme_path.read_text(errors="ignore")

    # Build a list of (line_offset, section_name) so we can lookup a
    # current section per match.
    sections: list[tuple[int, str]] = []
    for m in _HEADING_RE.finditer(text):
        sections.append((m.start(), m.group(1)))

    def _section_at(pos: int) -> str:
        cur = "Uncategorized"
        for off, name in sections:
            if off <= pos:
                cur = name
            else:
                break
        return cur

    seen_urls: set[str] = set()
    out = []
    for m in _LINK_RE.finditer(text):
        title, url, blurb = m.group(1), m.group(2), m.group(3).strip(" -")
        if not url.startswith("http"):
            continue
        if url in seen_urls:
            continue
        seen_urls.add(url)
        section = _section_at(m.start())
        # Skip table-of-contents and acknowledgement sections.
        if section.lower() in ("table of contents", "contributors",
                               "acknowledgements", "other lists of postmortems"):
            continue
        tags: set[str] = set()
        if section.lower() != "uncategorized":
            tags.add(section.lower().replace(" ", "-").replace("/", "-"))
        haystack = (title + " " + url + " " + blurb).lower()
        for kw, tag in _TAG_HINTS.items():
            if kw in haystack:
                tags.add(tag)
        elem = {
            "id": f"danluu_postmortems/{re.sub(r'[^a-z0-9]+', '-', title.lower())[:80]}",
            "source": "danluu_postmortems",
            "kind": "post_mortem",
            "title": title,
            "intent_md": _intent_md_for(title, url, blurb, sorted(tags)),
            "repo": None,
            "repo_clone_url": None,
            "language": None,
            "ground_truth": {
                "kind": "root_cause",
                "files_touched": None,
                "root_cause_keywords": sorted(tags),
                "outcome": "incident",
                "patch_uri": url,
            },
            "metadata": {
                "tags": sorted(tags),
                "source_url": url,
                "blurb": blurb,
            },
        }
        out.append(elem)
    return out


def ingest() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUT_DIR / "danluu_postmortems.jsonl"
    if out_path.exists() and out_path.stat().st_size > 0:
        existing = sum(1 for _ in out_path.open())
        print(f"[skip] postmortems -> {out_path} ({existing} rows)",
              file=sys.stderr)
        return existing

    if not CLONE_DIR.exists():
        CLONE_DIR.parent.mkdir(parents=True, exist_ok=True)
        print(f"[clone] {REPO_URL}", file=sys.stderr)
        subprocess.run(["git", "clone", "--depth", "1", REPO_URL,
                        str(CLONE_DIR)], check=True, capture_output=True)

    readme = CLONE_DIR / "README.md"
    if not readme.exists():
        print("[err] no README.md in cloned repo", file=sys.stderr)
        return 0

    elements = _parse_readme(readme)
    with out_path.open("w") as f:
        for e in elements:
            f.write(json.dumps(e) + "\n")
    print(f"[done] wrote {len(elements)} post-mortem elements to {out_path}",
          file=sys.stderr)
    return len(elements)


if __name__ == "__main__":
    ingest()
