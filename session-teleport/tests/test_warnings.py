"""Tests for security warnings module."""

from unittest.mock import patch
from io import StringIO

from session_teleport.security.warnings import (
    warn_secrets_in_content,
    warn_platform_mismatch,
    warn_cwd_mismatch,
)


def test_warn_secrets_clean_content():
    """Clean content should return True (proceed) without prompting."""
    result = warn_secrets_in_content("just some normal code here")
    assert result is True


def test_warn_secrets_detected_user_confirms():
    """Content with secrets should prompt; user says yes."""
    content = "my key is sk-abcdefghijklmnopqrstuvwxyz here"
    with patch("click.confirm", return_value=True):
        result = warn_secrets_in_content(content)
    assert result is True


def test_warn_secrets_detected_user_declines():
    """Content with secrets should prompt; user says no."""
    content = "my key is sk-abcdefghijklmnopqrstuvwxyz here"
    with patch("click.confirm", return_value=False):
        result = warn_secrets_in_content(content)
    assert result is False


def test_warn_platform_mismatch_same(capsys):
    """Same platform should not warn."""
    warn_platform_mismatch("linux", "linux")
    captured = capsys.readouterr()
    assert "mismatch" not in captured.out.lower()


def test_warn_platform_mismatch_different(capsys):
    """Different platforms should warn."""
    warn_platform_mismatch("darwin", "linux")
    captured = capsys.readouterr()
    assert "mismatch" in captured.out.lower() or "Platform" in captured.out


def test_warn_cwd_mismatch_none(capsys):
    """No target dir should not warn."""
    warn_cwd_mismatch("/home/user/project", None)
    captured = capsys.readouterr()
    assert "differs" not in captured.out.lower()


def test_warn_cwd_mismatch_different(capsys):
    """Different CWD should warn."""
    warn_cwd_mismatch("/home/user/project", "/tmp/other")
    captured = capsys.readouterr()
    assert "differs" in captured.out.lower() or "directory" in captured.out.lower()
