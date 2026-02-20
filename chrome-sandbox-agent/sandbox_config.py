"""
sandbox_config.py - Configuration system for Chrome sandbox workspaces.

Supports loading configuration from (in priority order):
  1. Constructor arguments (highest priority)
  2. Environment variables (SANDBOX_*)
  3. Config file (sandbox.config.json)
  4. Defaults (lowest priority)

The key concept is the "workspace": a host directory that gets bind-mounted
read-write into the sandbox so the agent's work persists after exit.

Example sandbox.config.json:
{
    "workspace": "./my-project",
    "policy": "TRACE_ALL",
    "network": false,
    "readonly_paths": ["/usr/local/lib", "/usr/local/bin"],
    "allowed_paths": ["/opt/tools"],
    "sandbox_workspace_path": "/workspace"
}
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# Default config file name (looked up relative to CWD)
CONFIG_FILENAME = "sandbox.config.json"


@dataclass
class SandboxConfig:
    """Full sandbox configuration with workspace support.

    Attributes:
        workspace: Host directory to mount read-write in the sandbox.
            Resolved to absolute path. Created if it doesn't exist.
        sandbox_workspace_path: Path where workspace appears inside the sandbox.
            Default "/workspace". The agent sees this as its working directory.
        policy: Seccomp-BPF policy level ("STRICT", "PERMISSIVE", "TRACE_ALL").
        network: Whether to enable network access inside the sandbox.
        readonly_paths: Host paths to mount read-only (runtimes, tools).
        allowed_paths: Additional host paths to mount read-write.
        exec_policy: Exec policy ("CHROME", "BROKERED", "BLOCKED").
    """

    workspace: Optional[str] = None
    sandbox_workspace_path: str = "/workspace"
    policy: str = "TRACE_ALL"
    network: bool = False
    readonly_paths: list[str] = field(default_factory=lambda: ["/usr/local/lib", "/usr/local/bin"])
    allowed_paths: list[str] = field(default_factory=list)
    exec_policy: str = "BROKERED"

    def __post_init__(self):
        # Resolve workspace to absolute path
        if self.workspace:
            self.workspace = str(Path(self.workspace).resolve())

    @classmethod
    def load(cls,
             config_file: Optional[str] = None,
             workspace: Optional[str] = None,
             policy: Optional[str] = None,
             network: Optional[bool] = None,
             readonly_paths: Optional[list[str]] = None,
             allowed_paths: Optional[list[str]] = None,
             sandbox_workspace_path: Optional[str] = None,
             exec_policy: Optional[str] = None) -> "SandboxConfig":
        """Load config from file + env vars + explicit args.

        Priority: explicit args > env vars > config file > defaults.
        """
        # Start with defaults
        cfg = {}

        # Layer 1: Config file
        file_path = config_file or CONFIG_FILENAME
        if os.path.exists(file_path):
            with open(file_path) as f:
                file_cfg = json.load(f)
            cfg.update(file_cfg)

        # Layer 2: Environment variables
        env_map = {
            "SANDBOX_WORKSPACE": "workspace",
            "SANDBOX_WORKSPACE_PATH": "sandbox_workspace_path",
            "SANDBOX_POLICY": "policy",
            "SANDBOX_NETWORK": "network",
            "SANDBOX_READONLY_PATHS": "readonly_paths",
            "SANDBOX_ALLOWED_PATHS": "allowed_paths",
            "SANDBOX_EXEC_POLICY": "exec_policy",
        }
        for env_key, cfg_key in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                if cfg_key == "network":
                    cfg[cfg_key] = val.lower() in ("1", "true", "yes")
                elif cfg_key in ("readonly_paths", "allowed_paths"):
                    cfg[cfg_key] = [p.strip() for p in val.split(":") if p.strip()]
                else:
                    cfg[cfg_key] = val

        # Layer 3: Explicit constructor args (highest priority)
        if workspace is not None:
            cfg["workspace"] = workspace
        if sandbox_workspace_path is not None:
            cfg["sandbox_workspace_path"] = sandbox_workspace_path
        if policy is not None:
            cfg["policy"] = policy
        if network is not None:
            cfg["network"] = network
        if readonly_paths is not None:
            cfg["readonly_paths"] = readonly_paths
        if allowed_paths is not None:
            cfg["allowed_paths"] = allowed_paths
        if exec_policy is not None:
            cfg["exec_policy"] = exec_policy

        return cls(**cfg)

    def ensure_workspace(self) -> Optional[str]:
        """Create the workspace directory on the host if it doesn't exist.

        Returns the absolute path, or None if no workspace configured.
        """
        if not self.workspace:
            return None
        os.makedirs(self.workspace, exist_ok=True)
        return self.workspace

    def get_all_allowed_paths(self) -> list[str]:
        """Get all read-write paths including the workspace."""
        paths = list(self.allowed_paths)
        if self.workspace:
            paths.append(self.workspace)
        return paths

    def save(self, path: Optional[str] = None):
        """Save current config to a JSON file."""
        out_path = path or CONFIG_FILENAME
        data = {
            "workspace": self.workspace,
            "sandbox_workspace_path": self.sandbox_workspace_path,
            "policy": self.policy,
            "network": self.network,
            "readonly_paths": self.readonly_paths,
            "allowed_paths": self.allowed_paths,
            "exec_policy": self.exec_policy,
        }
        with open(out_path, "w") as f:
            json.dump(data, f, indent=2)
            f.write("\n")

    def summary(self) -> str:
        """Human-readable config summary."""
        lines = []
        if self.workspace:
            lines.append(f"  Workspace: {self.workspace} -> {self.sandbox_workspace_path}")
        else:
            lines.append("  Workspace: (none - /tmp only, ephemeral)")
        lines.append(f"  Policy: {self.policy}")
        lines.append(f"  Network: {'enabled' if self.network else 'disabled'}")
        if self.readonly_paths:
            lines.append(f"  Read-only: {', '.join(self.readonly_paths)}")
        if self.allowed_paths:
            lines.append(f"  Read-write: {', '.join(self.allowed_paths)}")
        lines.append(f"  Exec policy: {self.exec_policy}")
        return "\n".join(lines)


if __name__ == "__main__":
    # Quick demo
    cfg = SandboxConfig.load()
    print("Current config:")
    print(cfg.summary())
    print()

    # Show how workspace would work
    cfg2 = SandboxConfig.load(workspace="./my-project")
    print("With workspace:")
    print(cfg2.summary())
