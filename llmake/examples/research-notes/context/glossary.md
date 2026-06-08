# Glossary (shared context)

- **Target**: one node in the build graph; compiles to a single artifact.
- **Artifact**: the saved output of a target (markdown by default).
- **Provider**: an inference backend — a chat model or a coding agent.
- **Snapshot**: a git commit+tag of the build artifacts.
- **Incremental build**: only targets whose inputs changed are recomputed.
