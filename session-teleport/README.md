# session-teleport

Teleport Claude Code and OpenAI Codex CLI sessions between machines.

## What it does

When you're working with an AI coding agent on Machine A and need to continue on Machine B, `session-teleport` packages your entire session state — conversation history, git state, environment context — into an encrypted portable bundle that can be transferred and resumed.

## Supported Providers

- **Claude Code** (`~/.claude/`) — conversation logs, subagent data, tool results, settings
- **OpenAI Codex CLI** (`~/.codex/`) — session data and conversation history

## Install

```bash
pip install -e .
```

## Quick Start

### Export a session (Machine A)

```bash
# List available sessions
stp list

# Export a session to a file
stp export <session-id> -o my-session.stp

# Export without encryption
stp export <session-id> --no-encrypt -o my-session.stp
```

### Import a session (Machine B)

```bash
# Import from file
stp import my-session.stp

# Import with a different working directory
stp import my-session.stp --target-dir /path/to/project

# Preview without changes
stp import my-session.stp --dry-run
```

### Direct peer-to-peer transfer

```bash
# On Machine B (receiver):
stp receive --method peer --port 9876

# On Machine A (sender) — enter the auth code shown by the receiver:
stp send <session-id> --method peer --host 192.168.1.100
```

### Relay transfer (when machines can't connect directly)

```bash
# Start a relay (on any reachable server):
stp relay-server --port 8765

# On Machine A:
stp send <session-id> --method relay --relay-url http://relay:8765

# On Machine B — use the pickup code shown to sender:
stp receive --method relay --relay-url http://relay:8765 --code <code>
```

### Inspect a bundle

```bash
stp inspect my-session.stp
```

## What's in a bundle

A `.stp` file is an encrypted tar.gz containing:

| Component | Contents |
|-----------|----------|
| `session/` | Provider-specific session files (conversation log, subagents, tool results) |
| `git/` | Branch, commit, remote, uncommitted changes as patches, recent log |
| `env/` | Filtered environment variables (secrets auto-redacted), tool versions |
| `manifest.json` | Bundle metadata (provider, source host/platform, checksums) |

## Security

- Bundles are **encrypted by default** using AES-128-CBC (Fernet) with PBKDF2-derived keys
- Environment variables matching secret patterns (API keys, tokens, passwords) are **automatically redacted**
- Conversation logs are **scanned for potential secrets** before export, with a user confirmation prompt
- Peer transfers use a **one-time auth code** for authentication
- Relay bundles are **single-use** with configurable TTL expiry

## Architecture

```
session_teleport/
├── cli.py                 # Click CLI commands
├── core/
│   ├── bundle.py          # .stp bundle format (tar.gz + manifest)
│   ├── crypto.py          # Fernet encryption with PBKDF2
│   └── manifest.py        # Bundle metadata
├── providers/
│   ├── base.py            # Abstract provider interface
│   ├── claude_code.py     # Claude Code session handling
│   └── codex_cli.py       # Codex CLI session handling
├── collectors/
│   ├── git_state.py       # Git branch, diff, patches
│   ├── env_snapshot.py    # Filtered environment capture
│   └── tool_versions.py   # Python, node, git versions
├── transfer/
│   ├── file_transfer.py   # Local file export/import
│   ├── peer.py            # Direct TCP with auth code
│   └── relay.py           # HTTP relay server + client
└── security/
    ├── secret_filter.py   # Entropy-based secret detection
    └── warnings.py        # User-facing security prompts
```
