#!/usr/bin/env python3
"""
Quick smoke test that validates everything except the Modal GPU call.

Run this to verify your setup before deploying:
    python test_local.py
"""

import sys
from repo_fetcher import parse_github_url, fetch_repo, PRIMARY_LANGUAGES


def test_url_parsing():
    cases = [
        ("https://github.com/owner/repo", ("owner", "repo")),
        ("https://github.com/owner/repo.git", ("owner", "repo")),
        ("https://github.com/owner/repo/tree/main/src", ("owner", "repo")),
    ]
    for url, expected in cases:
        result = parse_github_url(url)
        assert result == expected, f"parse_github_url({url!r}) = {result}, expected {expected}"
    print("  [PASS] URL parsing")


def test_fetch_repo():
    repo = fetch_repo("https://github.com/ucsb-mlsec/VulnLLM-R", max_files=5)
    assert repo.name == "ucsb-mlsec/VulnLLM-R"
    assert "python" in repo.languages
    assert len(repo.files) == 5
    assert all(f.content for f in repo.files)
    assert all(f.language for f in repo.files)
    print(f"  [PASS] Repo fetch ({repo.name}: {len(repo.files)} files, langs={list(repo.languages.keys())})")


def test_modal_import():
    try:
        import modal  # noqa: F401
        print("  [PASS] Modal SDK installed")
    except ImportError:
        print("  [FAIL] Modal SDK not installed -- run: pip install modal")
        return False
    return True


def test_modal_service_syntax():
    """Just verify the Modal service file parses without errors."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("modal_service", "modal_service.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
        print("  [PASS] modal_service.py loads without errors")
    except Exception as e:
        print(f"  [FAIL] modal_service.py failed to load: {e}")
        return False
    return True


def main():
    print("\nVulnLLM Analyzer - Smoke Tests\n")
    all_pass = True

    test_url_parsing()

    print("  [....] Fetching repo (this clones from GitHub)...")
    try:
        test_fetch_repo()
    except Exception as e:
        print(f"  [FAIL] Repo fetch: {e}")
        all_pass = False

    if not test_modal_import():
        all_pass = False

    if not test_modal_service_syntax():
        all_pass = False

    print()
    if all_pass:
        print("All tests passed. Next steps:")
        print("  1. modal token set --token-id <id> --token-secret <secret>")
        print("  2. modal deploy modal_service.py")
        print("  3. python analyzer.py https://github.com/some/repo")
    else:
        print("Some tests failed. Fix the issues above before deploying.")
        sys.exit(1)


if __name__ == "__main__":
    main()
