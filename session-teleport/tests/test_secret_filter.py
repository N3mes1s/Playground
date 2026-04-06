"""Tests for secret filtering."""

from session_teleport.security.secret_filter import (
    filter_env,
    is_secret_env_name,
    looks_like_secret_value,
    scan_text_for_secrets,
    shannon_entropy,
)


def test_filter_env_keeps_safe_vars():
    env = {"PATH": "/usr/bin", "HOME": "/home/user", "SHELL": "/bin/bash"}
    safe, redacted = filter_env(env)
    assert safe == env
    assert redacted == []


def test_filter_env_redacts_secrets():
    env = {
        "PATH": "/usr/bin",
        "OPENAI_API_KEY": "sk-1234567890abcdef",
        "ANTHROPIC_API_KEY": "sk-ant-abc123",
        "MY_PASSWORD": "hunter2",
    }
    safe, redacted = filter_env(env)
    assert "PATH" in safe
    assert "OPENAI_API_KEY" not in safe
    assert "ANTHROPIC_API_KEY" not in safe
    assert "MY_PASSWORD" not in safe
    assert len(redacted) == 3


def test_shannon_entropy():
    assert shannon_entropy("aaaa") < 1.0
    assert shannon_entropy("abcdefghij") > 3.0
    assert shannon_entropy("") == 0.0


def test_looks_like_secret_value():
    assert looks_like_secret_value("sk-1234567890abcdefghijklmnop")
    assert looks_like_secret_value("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh")
    assert not looks_like_secret_value("hello")
    assert not looks_like_secret_value("/usr/local/bin")


def test_is_secret_env_name():
    assert is_secret_env_name("OPENAI_API_KEY")
    assert is_secret_env_name("MY_SECRET")
    assert is_secret_env_name("DATABASE_TOKEN")
    assert not is_secret_env_name("PATH")
    assert not is_secret_env_name("HOME")


def test_scan_text_for_secrets():
    text = "Here is my key: sk-abcdefghijklmnopqrstuvwxyz and done"
    warnings = scan_text_for_secrets(text)
    assert any("OpenAI" in w for w in warnings)

    clean_text = "Just some normal code here"
    assert scan_text_for_secrets(clean_text) == []
