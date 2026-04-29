"""Tiny GitHub helpers. Public-API only, no auth required for public repos.

Set GITHUB_TOKEN in env to lift rate limits.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

import requests


_PR_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<num>\d+)"
)
_ISSUE_URL_RE = re.compile(
    r"https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/issues/(?P<num>\d+)"
)


@dataclass
class PullRequest:
    owner: str
    repo: str
    number: int
    title: str
    body: str
    diff: str
    base_sha: str
    head_sha: str
    url: str


@dataclass
class Issue:
    owner: str
    repo: str
    number: int
    title: str
    body: str
    labels: list[str]
    url: str


def _headers() -> dict:
    h = {"Accept": "application/vnd.github+json"}
    tok = os.environ.get("GITHUB_TOKEN", "").strip()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def parse_pr_url(url: str) -> tuple[str, str, int]:
    m = _PR_URL_RE.match(url.strip())
    if not m:
        raise ValueError(f"Not a GitHub PR URL: {url!r}")
    return m["owner"], m["repo"], int(m["num"])


def parse_issue_url(url: str) -> tuple[str, str, int]:
    m = _ISSUE_URL_RE.match(url.strip())
    if not m:
        raise ValueError(f"Not a GitHub issue URL: {url!r}")
    return m["owner"], m["repo"], int(m["num"])


def fetch_pr(url: str, *, max_diff_chars: int = 60_000) -> PullRequest:
    owner, repo, num = parse_pr_url(url)
    api = f"https://api.github.com/repos/{owner}/{repo}/pulls/{num}"
    r = requests.get(api, headers=_headers(), timeout=30)
    r.raise_for_status()
    j = r.json()

    diff_headers = dict(_headers())
    diff_headers["Accept"] = "application/vnd.github.v3.diff"
    rd = requests.get(api, headers=diff_headers, timeout=30)
    rd.raise_for_status()
    diff = rd.text
    if len(diff) > max_diff_chars:
        diff = diff[:max_diff_chars] + f"\n\n... [truncated, {len(diff) - max_diff_chars} more chars] ..."

    return PullRequest(
        owner=owner,
        repo=repo,
        number=num,
        title=j.get("title", ""),
        body=j.get("body") or "",
        diff=diff,
        base_sha=j["base"]["sha"],
        head_sha=j["head"]["sha"],
        url=url,
    )


def fetch_issue(url: str) -> Issue:
    owner, repo, num = parse_issue_url(url)
    api = f"https://api.github.com/repos/{owner}/{repo}/issues/{num}"
    r = requests.get(api, headers=_headers(), timeout=30)
    r.raise_for_status()
    j = r.json()
    return Issue(
        owner=owner,
        repo=repo,
        number=num,
        title=j.get("title", ""),
        body=j.get("body") or "",
        labels=[l["name"] for l in j.get("labels", [])],
        url=url,
    )
