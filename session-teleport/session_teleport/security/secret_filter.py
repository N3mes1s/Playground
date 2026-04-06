"""Detect and filter secrets from environment variables and file contents."""

import math
import re

# Environment variable names that are safe to include
SAFE_ENV_NAMES = {
    "PATH", "HOME", "USER", "SHELL", "LANG", "LC_ALL", "LC_CTYPE",
    "TERM", "TERM_PROGRAM", "COLORTERM", "EDITOR", "VISUAL", "PAGER",
    "PWD", "OLDPWD", "SHLVL", "LOGNAME", "HOSTNAME",
    "VIRTUAL_ENV", "CONDA_DEFAULT_ENV", "CONDA_PREFIX",
    "NVM_DIR", "NVM_BIN", "NODE_VERSION", "NODE_PATH",
    "PYTHON_VERSION", "PYTHONPATH", "PYTHONDONTWRITEBYTECODE",
    "GOPATH", "GOROOT", "CARGO_HOME", "RUSTUP_HOME",
    "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
    "XDG_RUNTIME_DIR", "XDG_SESSION_TYPE",
    "DISPLAY", "WAYLAND_DISPLAY",
    "TMUX", "TMUX_PANE", "STY",
    "SSH_AUTH_SOCK", "SSH_CONNECTION",
    "DOCKER_HOST", "COMPOSE_PROJECT_NAME",
    "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL",
    "GIT_COMMITTER_NAME", "GIT_COMMITTER_EMAIL",
}

# Patterns that indicate a secret environment variable
SECRET_NAME_PATTERNS = [
    re.compile(r".*_KEY$", re.IGNORECASE),
    re.compile(r".*_SECRET$", re.IGNORECASE),
    re.compile(r".*_TOKEN$", re.IGNORECASE),
    re.compile(r".*_PASSWORD$", re.IGNORECASE),
    re.compile(r".*_PASSWD$", re.IGNORECASE),
    re.compile(r".*_CREDENTIALS?$", re.IGNORECASE),
    re.compile(r".*_API_KEY$", re.IGNORECASE),
    re.compile(r"^(ANTHROPIC|OPENAI|OPENROUTER|COHERE|HUGGINGFACE|HF)_.*", re.IGNORECASE),
    re.compile(r"^AWS_(ACCESS|SECRET|SESSION).*", re.IGNORECASE),
    re.compile(r"^(GITHUB|GITLAB|BITBUCKET)_TOKEN$", re.IGNORECASE),
    re.compile(r"^DATABASE_URL$", re.IGNORECASE),
    re.compile(r"^REDIS_URL$", re.IGNORECASE),
    re.compile(r"^MONGO_URI$", re.IGNORECASE),
    re.compile(r"^STRIPE_.*", re.IGNORECASE),
    re.compile(r"^SENDGRID_.*", re.IGNORECASE),
    re.compile(r"^TWILIO_.*", re.IGNORECASE),
]


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def looks_like_secret_value(value: str) -> bool:
    """Heuristic check if a value looks like an API key or secret."""
    if len(value) < 16:
        return False
    if shannon_entropy(value) > 4.0 and len(value) >= 20:
        return True
    secret_prefixes = ["sk-", "pk-", "ghp_", "gho_", "ghu_", "ghs_", "glpat-",
                       "xoxb-", "xoxp-", "AKIA", "eyJ"]
    return any(value.startswith(p) for p in secret_prefixes)


def is_secret_env_name(name: str) -> bool:
    """Check if an environment variable name suggests it holds a secret."""
    return any(p.match(name) for p in SECRET_NAME_PATTERNS)


def filter_env(env: dict[str, str]) -> tuple[dict[str, str], list[str]]:
    """Filter environment variables, returning (safe_env, redacted_names).

    Returns safe variables and a list of variable names that were redacted.
    """
    safe = {}
    redacted = []

    for name, value in sorted(env.items()):
        if name in SAFE_ENV_NAMES:
            safe[name] = value
        elif is_secret_env_name(name) or looks_like_secret_value(value):
            redacted.append(name)
        else:
            safe[name] = value

    return safe, redacted


def scan_text_for_secrets(text: str) -> list[str]:
    """Scan text content for potential secrets. Returns list of warnings."""
    warnings = []
    patterns = [
        (r"sk-[a-zA-Z0-9]{20,}", "OpenAI API key"),
        (r"ghp_[a-zA-Z0-9]{36}", "GitHub personal access token"),
        (r"glpat-[a-zA-Z0-9\-]{20,}", "GitLab personal access token"),
        (r"AKIA[0-9A-Z]{16}", "AWS access key ID"),
        (r"xox[bporas]-[a-zA-Z0-9\-]{10,}", "Slack token"),
        (r"-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----", "Private key"),
    ]
    for pattern, label in patterns:
        if re.search(pattern, text):
            warnings.append(f"Possible {label} detected in session data")
    return warnings
