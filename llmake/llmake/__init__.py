"""
llmake — a build system for LLM inference workflows.

"GNU Autotools × Notion": treat your notes, specs, and context as *source*,
declare a DAG of prompt/agent steps in ``llmake.yaml``, and compile them into
cached, shareable artifacts. Re-running only recomputes what changed.

See DESIGN.md for the reasoning, and README.md for usage.
"""

from .runner import build, status
from .spec import load_workflow

__version__ = "0.1.0"

__all__ = ["load_workflow", "build", "status", "__version__"]
