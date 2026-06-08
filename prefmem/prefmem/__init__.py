"""PrefMem -- a preference-memory layer that makes your agents learn each user's
preferences from their edits.

    from prefmem import PrefMem
    pm = PrefMem(store="prefmem.db")
    ctx = pm.context(user="u1", task="email")
    prompt = ctx.guidance() + "\\n\\n" + user_msg
    turn = ctx.log(query=user_msg, response=run_your_llm(prompt))
    turn.edit(user_final_text)
    pm.learn(user="u1", task="email")
"""

from .client import Context, PrefMem, Turn
from .schema import Preference, Signal, Status, Trajectory

__version__ = "0.1.0"
__all__ = ["PrefMem", "Context", "Turn", "Signal", "Status",
           "Trajectory", "Preference", "__version__"]
