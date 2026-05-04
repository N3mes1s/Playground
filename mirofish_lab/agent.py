"""Agent wrapper.

Built on CAMEL-AI's ChatAgent (the same engine MiroFish runs on internally).
Falls back to direct OpenAI Chat Completions if CAMEL-AI is unavailable or
fails to instantiate, so the experiments remain runnable even across CAMEL
API drift. Memory uses our LocalMemory (see memory.py), not Zep.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from mirofish_lab.config import Config, make_openai_client
from mirofish_lab.memory import LocalMemory
from mirofish_lab.personas import Persona


@dataclass
class AgentResponse:
    agent_name: str
    content: str
    tokens_in: int = 0
    tokens_out: int = 0


class Agent:
    """Persona-bound chat agent with persistent local memory.

    Uses CAMEL-AI's ChatAgent when available; otherwise OpenAI directly.
    Either way, the persona's system prompt is the seed and LocalMemory
    holds the running transcript.
    """

    def __init__(
        self,
        persona: Persona,
        cfg: Config,
        *,
        persistent: bool = False,
        temperature: float = 0.7,
    ):
        self.persona = persona
        self.cfg = cfg
        self.temperature = temperature
        self.memory = LocalMemory(
            persona.name,
            root=cfg.memory_dir if persistent else None,
        )
        self._camel_agent: Any | None = None
        self._client = make_openai_client(cfg)
        self._try_init_camel()

    def _try_init_camel(self) -> None:
        try:
            from camel.agents import ChatAgent
            from camel.messages import BaseMessage
            from camel.models import ModelFactory
            from camel.types import ModelPlatformType
        except Exception:
            self._camel_agent = None
            return

        try:
            model_kwargs: dict = {
                "model_platform": ModelPlatformType.OPENAI,
                "model_type": self.cfg.model,
                "api_key": self.cfg.api_key,
                "model_config_dict": {
                    "max_completion_tokens": self.cfg.max_tokens,
                },
            }
            if self.cfg.base_url:
                model_kwargs["url"] = self.cfg.base_url
            model = ModelFactory.create(**model_kwargs)

            system_msg = BaseMessage.make_assistant_message(
                role_name=self.persona.name,
                content=self.persona.system_prompt,
            )
            self._camel_agent = ChatAgent(system_message=system_msg, model=model)
            self._BaseMessage = BaseMessage
        except Exception:
            self._camel_agent = None

    @property
    def using_camel(self) -> bool:
        return self._camel_agent is not None

    def respond(self, user_message: str, *, tags: tuple[str, ...] = ()) -> AgentResponse:
        self.memory.add("user", user_message, tags=tags)
        if self._camel_agent is not None:
            try:
                msg = self._BaseMessage.make_user_message(
                    role_name="User", content=user_message
                )
                result = self._camel_agent.step(msg)
                content = result.msgs[0].content if result.msgs else ""
                ti = getattr(result.info.get("usage", {}), "get", lambda k, d=0: d)("prompt_tokens", 0) if hasattr(result, "info") else 0
                to = getattr(result.info.get("usage", {}), "get", lambda k, d=0: d)("completion_tokens", 0) if hasattr(result, "info") else 0
            except Exception:
                content, ti, to = self._openai_call(user_message)
        else:
            content, ti, to = self._openai_call(user_message)

        self.memory.add("assistant", content, tags=tags)
        return AgentResponse(self.persona.name, content, tokens_in=ti, tokens_out=to)

    def _openai_call(self, user_message: str) -> tuple[str, int, int]:
        # Build messages: system + history + new user message.
        msgs: list[dict] = [{"role": "system", "content": self.persona.system_prompt}]
        for r in self.memory.all():
            if r.role in ("user", "assistant"):
                msgs.append({"role": r.role, "content": r.content})
        # The just-added user message is already in memory; avoid double-count.
        # We re-add explicitly only if memory.add hasn't yet been invoked;
        # in respond() it has, so skip.
        # gpt-5.x and o-series use max_completion_tokens; older models also accept it.
        resp = self._client.chat.completions.create(
            model=self.cfg.model,
            messages=msgs,
            max_completion_tokens=self.cfg.max_tokens,
        )
        choice = resp.choices[0].message.content or ""
        usage = resp.usage
        ti = usage.prompt_tokens if usage else 0
        to = usage.completion_tokens if usage else 0
        return choice, ti, to
