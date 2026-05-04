"""Shared substrate for the MiroFish-style coding-agent experiments.

Built on CAMEL-AI (the same engine MiroFish uses underneath) plus a local
file-backed memory layer in place of Zep Cloud. Designed to be small,
inspectable, and reusable across the four playground experiments.
"""

from mirofish_lab.config import Config, load_config
from mirofish_lab.agent import Agent, AgentResponse
from mirofish_lab.memory import LocalMemory
from mirofish_lab.personas import Persona
from mirofish_lab.simulation import parallel_run, debate, round_table
from mirofish_lab.report import Report

__all__ = [
    "Config",
    "load_config",
    "Agent",
    "AgentResponse",
    "LocalMemory",
    "Persona",
    "parallel_run",
    "debate",
    "round_table",
    "Report",
]
