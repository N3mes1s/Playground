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

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
PARALLEL_API_KEY = os.getenv("PARALLEL_API_KEY")

MODEL = os.getenv("FINANCE_AGENT_MODEL", "claude-opus-4-7")
TICK_INTERVAL = int(os.getenv("FINANCE_AGENT_TICK_INTERVAL", "300"))

MAX_POSITION_PCT = 0.20
MAX_POSITIONS = 10
MIN_CASH_PCT = 0.05
DAILY_LOSS_HALT_PCT = 0.05
MAX_ORDER_PCT = 0.10
