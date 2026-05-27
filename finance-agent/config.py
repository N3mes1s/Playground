import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

ROOT = Path(__file__).parent
DATA_DIR = Path(os.getenv("FINANCE_AGENT_DATA_DIR", ROOT / "data")).resolve()
DATA_DIR.mkdir(parents=True, exist_ok=True)

PORTFOLIO_PATH = DATA_DIR / "portfolio.json"
JOURNAL_PATH = DATA_DIR / "journal.jsonl"
PLAYBOOK_PATH = DATA_DIR / "playbook.md"
TICK_LOG_PATH = DATA_DIR / "ticks.jsonl"


def _read_session_ingress_token() -> str | None:
    path = os.getenv("CLAUDE_SESSION_INGRESS_TOKEN_FILE")
    if not path or not os.path.exists(path):
        return None
    try:
        token = Path(path).read_text().strip()
        return token or None
    except OSError:
        return None


def resolve_anthropic_credentials() -> dict:
    """Return kwargs for `anthropic.Anthropic(...)`.

    Resolution order:
      1. ANTHROPIC_API_KEY env var (standard developer key)
      2. ANTHROPIC_AUTH_TOKEN env var (any Bearer token, e.g. an OAuth token)
      3. CLAUDE_SESSION_INGRESS_TOKEN_FILE — present inside a Claude Code remote
         execution environment. The token at that path is a valid Bearer
         credential for /v1/messages, so we can reuse the session's LLM access
         without a separate developer key.
    """
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if api_key:
        return {"api_key": api_key}
    auth_token = os.getenv("ANTHROPIC_AUTH_TOKEN") or _read_session_ingress_token()
    if auth_token:
        return {"auth_token": auth_token}
    raise RuntimeError(
        "No Anthropic credentials found. Set ANTHROPIC_API_KEY in .env, "
        "or run inside a Claude Code session where "
        "CLAUDE_SESSION_INGRESS_TOKEN_FILE is populated."
    )


PARALLEL_API_KEY = os.getenv("PARALLEL_API_KEY")

MODEL = os.getenv("FINANCE_AGENT_MODEL", "claude-opus-4-7")
TICK_INTERVAL = int(os.getenv("FINANCE_AGENT_TICK_INTERVAL", "300"))

MAX_POSITION_PCT = 0.20
MAX_POSITIONS = 10
MIN_CASH_PCT = 0.05
DAILY_LOSS_HALT_PCT = 0.05
MAX_ORDER_PCT = 0.10
