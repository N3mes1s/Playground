"""Env loading + runtime model availability check."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI


@dataclass(frozen=True)
class Config:
    api_key: str
    model: str
    base_url: str | None
    memory_dir: Path
    max_tokens: int


def load_config(env_file: Path | str | None = None) -> Config:
    if env_file:
        load_dotenv(env_file)
    else:
        load_dotenv()

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError(
            "OPENAI_API_KEY is not set. Copy .env.example to .env and fill it in."
        )

    model = os.environ.get("MODEL", "gpt-5.4-mini").strip()
    base_url = os.environ.get("OPENAI_BASE_URL", "").strip() or None
    memory_dir = Path(
        os.environ.get("MIROFISH_MEMORY_DIR", "").strip() or ".mirofish_memory"
    ).resolve()
    memory_dir.mkdir(parents=True, exist_ok=True)
    max_tokens = int(os.environ.get("MAX_TOKENS", "4096"))

    return Config(
        api_key=api_key,
        model=model,
        base_url=base_url,
        memory_dir=memory_dir,
        max_tokens=max_tokens,
    )


def make_openai_client(cfg: Config) -> OpenAI:
    kwargs: dict = {"api_key": cfg.api_key}
    if cfg.base_url:
        kwargs["base_url"] = cfg.base_url
    return OpenAI(**kwargs)


def verify_model(cfg: Config) -> None:
    """Hit /v1/models and confirm cfg.model is available. Raises otherwise."""
    client = make_openai_client(cfg)
    try:
        listing = client.models.list()
    except Exception as exc:
        raise RuntimeError(
            f"Could not list models from {cfg.base_url or 'https://api.openai.com'}: {exc}"
        ) from exc

    available = sorted({m.id for m in listing.data})
    if cfg.model not in available:
        sample = ", ".join(available[:25]) + (" ..." if len(available) > 25 else "")
        raise RuntimeError(
            f"Model '{cfg.model}' not found on this account. "
            f"Available models include: {sample}"
        )
