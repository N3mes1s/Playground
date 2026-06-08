# Interview transcript (excerpt)

**Q:** What breaks down with your current LLM workflow?

**A:** Everything is a one-off. I paste context into a chat, get an output,
copy it somewhere, then lose track of which inputs produced it. When I change
one source doc I have no idea what's now stale.

**Q:** What would "good" look like?

**A:** Something like a Makefile for prompts. I declare my sources, my prompts,
and how steps depend on each other. I run one command and it rebuilds only
what changed. The outputs are files I can diff, version, and hand to someone.

**Q:** Chat models only, or agents too?

**A:** Agents too — sometimes a step is "go read these files and refactor,"
not just "answer this question." I want the same harness for both.
