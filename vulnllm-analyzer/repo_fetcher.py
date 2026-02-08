"""
GitHub repository fetcher and language detector.

Clones a GitHub repo (or fetches via API), detects the primary languages,
and extracts source files for vulnerability analysis.
"""

import re
import tempfile
import subprocess
import os
from pathlib import Path
from dataclasses import dataclass, field

# Language extensions supported by VulnLLM-R (primary: C, Python, Java)
# Extended with closely related languages for broader coverage.
LANGUAGE_MAP = {
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".py": "python",
    ".java": "java",
    ".js": "javascript",
    ".ts": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".scala": "scala",
    ".sol": "solidity",
}

# VulnLLM-R was trained on these -- best accuracy
PRIMARY_LANGUAGES = {"c", "cpp", "python", "java"}

# Skip these directories
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", "vendor",
    "dist", "build", ".tox", ".eggs", "target", ".gradle",
    "third_party", "thirdparty", "3rdparty", "external",
}

# Max file size to analyze (100KB) -- larger files are usually generated
MAX_FILE_SIZE = 100_000

# Max files to analyze per repo (avoid runaway costs)
MAX_FILES = 200


@dataclass
class SourceFile:
    path: str
    language: str
    content: str
    size: int


@dataclass
class RepoInfo:
    url: str
    name: str
    languages: dict[str, int] = field(default_factory=dict)
    files: list[SourceFile] = field(default_factory=list)
    total_files_found: int = 0
    skipped_files: int = 0


def parse_github_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL."""
    url = url.rstrip("/")
    # Handle various GitHub URL formats
    patterns = [
        r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$",
        r"github\.com/([^/]+)/([^/]+?)(?:/tree/.+)?$",
    ]
    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1), match.group(2)
    raise ValueError(f"Could not parse GitHub URL: {url}")


def clone_repo(url: str, target_dir: str, depth: int = 1) -> str:
    """Shallow-clone a GitHub repository."""
    # Normalize URL to HTTPS .git format
    owner, repo = parse_github_url(url)
    clone_url = f"https://github.com/{owner}/{repo}.git"

    subprocess.run(
        ["git", "clone", "--depth", str(depth), "--single-branch", clone_url, target_dir],
        check=True,
        capture_output=True,
        timeout=120,
    )
    return target_dir


def detect_languages(repo_dir: str) -> dict[str, int]:
    """Walk the repo and count files per detected language."""
    counts: dict[str, int] = {}
    for root, dirs, filenames in os.walk(repo_dir):
        # Prune skipped directories in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            lang = LANGUAGE_MAP.get(ext)
            if lang:
                counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: -x[1]))


def collect_files(
    repo_dir: str,
    languages: set[str] | None = None,
    max_files: int = MAX_FILES,
) -> tuple[list[SourceFile], int, int]:
    """
    Collect source files from the repo.

    Args:
        repo_dir: Path to the cloned repo.
        languages: If set, only collect files in these languages.
                   If None, collect all recognized languages.
        max_files: Maximum files to return.

    Returns:
        (files, total_found, skipped)
    """
    ext_filter = None
    if languages:
        ext_filter = {ext for ext, lang in LANGUAGE_MAP.items() if lang in languages}

    files: list[SourceFile] = []
    total_found = 0
    skipped = 0

    for root, dirs, filenames in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in filenames:
            ext = Path(fname).suffix.lower()
            lang = LANGUAGE_MAP.get(ext)
            if not lang:
                continue
            if ext_filter and ext not in ext_filter:
                continue

            total_found += 1
            fpath = os.path.join(root, fname)

            try:
                size = os.path.getsize(fpath)
            except OSError:
                skipped += 1
                continue

            if size > MAX_FILE_SIZE or size == 0:
                skipped += 1
                continue

            if len(files) >= max_files:
                skipped += 1
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
            except OSError:
                skipped += 1
                continue

            rel_path = os.path.relpath(fpath, repo_dir)
            files.append(SourceFile(
                path=rel_path,
                language=lang,
                content=content,
                size=size,
            ))

    # Sort: primary languages first, then by size descending (meatier files first)
    files.sort(key=lambda f: (f.language not in PRIMARY_LANGUAGES, -f.size))
    return files, total_found, skipped


def fetch_repo(
    url: str,
    languages: set[str] | None = None,
    max_files: int = MAX_FILES,
) -> RepoInfo:
    """
    Fetch a GitHub repo, detect languages, and collect source files.

    Args:
        url: GitHub repository URL.
        languages: Optional set of languages to focus on.
                   If None, auto-detects and uses all recognized languages.
        max_files: Max files to collect.

    Returns:
        RepoInfo with detected languages and collected source files.
    """
    owner, repo_name = parse_github_url(url)

    with tempfile.TemporaryDirectory(prefix="vulnllm_") as tmpdir:
        repo_dir = os.path.join(tmpdir, repo_name)
        clone_repo(url, repo_dir)

        detected_langs = detect_languages(repo_dir)
        files, total_found, skipped = collect_files(repo_dir, languages, max_files)

    return RepoInfo(
        url=url,
        name=f"{owner}/{repo_name}",
        languages=detected_langs,
        files=files,
        total_files_found=total_found,
        skipped_files=skipped,
    )
