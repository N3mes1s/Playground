# Playground Companion (iOS)

A native SwiftUI app for browsing this repository from a phone: it lists the
experiments, renders their READMEs and reports, walks their file trees, and can
hand any document to Claude for a summary or a question.

The first iOS experiment in the Playground, and the first non-Python one.

## ⚠️ Never built or run

This project was written in a Linux cloud container with no Xcode and no Swift
toolchain, so **it has never been compiled, and the simulator has never seen
it.** Claude Code's [iOS Simulator pane][sim] is local-only — in cloud and SSH
sessions Claude runs on a machine that can't reach the simulators on your Mac.

To actually build and run it, open this branch in a **local** Claude Code
Desktop session (or Xcode) on a Mac and ask Claude to build and run it in the
simulator. Expect to fix compile errors on the first pass.

[sim]: https://code.claude.com/docs/en/desktop-ios-simulator

## What it does

| Screen | Behavior |
|---|---|
| Experiment list | Top-level directories of the repo, each with the description its row in the root README table gives it. Searchable, pull-to-refresh. |
| Experiment detail | Renders the experiment's `README.md`; jumps into its file tree. |
| File browser | Recursive directory listing; opens text files, greys out binaries. |
| File viewer | Markdown rendered, or monospaced source with a toggle for `.md` files. |
| Ask Claude | Streams an answer about the open document — preset prompts (summarize / findings / explain) or a free-form question. |
| Settings | API key, optional GitHub token, model and effort, and which repo to point at. |

## Requirements

- Xcode 16 or later (the project uses file-system-synchronized groups, `objectVersion = 77`)
- iOS 17 deployment target
- No third-party dependencies — `URLSession`, SwiftUI, and Security.framework only

## Setup

1. Open `PlaygroundCompanion.xcodeproj`.
2. Set your own team / bundle identifier if you're running on a device.
3. Build and run.
4. In the app, open **Settings** and paste an Anthropic API key. Optionally add a
   read-only GitHub token to raise the API rate limit from 60/hour to 5,000/hour.

The app works without an API key — browsing is entirely GitHub-driven; only the
"Ask Claude" feature needs one.

## How the Claude integration works

There is no official Anthropic SDK for Swift, so `Services/ClaudeClient.swift`
speaks the Messages API over raw HTTP:

```
POST https://api.anthropic.com/v1/messages
x-api-key: <key>
anthropic-version: 2023-06-01
content-type: application/json

{"model": "claude-opus-5", "max_tokens": 16000, "stream": true,
 "output_config": {"effort": "medium"}, "system": "...", "messages": [...]}
```

Responses stream as SSE. The client iterates `URLSession.bytes(for:).lines`,
keeps `data:` lines, and yields the `text` of every `content_block_delta` whose
delta type is `text_delta` into an `AsyncThrowingStream<String, Error>`, so the
view appends tokens as they arrive. It also surfaces `stop_reason: "refusal"`
and API error envelopes as typed Swift errors.

Details worth knowing if you change it:

- **Models.** `claude-opus-5` (default), `claude-sonnet-5`, `claude-haiku-4-5`.
  Model IDs carry no date suffix.
- **Thinking is on by default on Opus 5** — the client never sends a `thinking`
  field, so it runs adaptive. `max_tokens` bounds thinking *and* response text
  together, which is why it's set to 16,000 rather than sized to the expected
  answer.
- **Effort** goes inside `output_config`, not at the top level, and is omitted
  for Haiku 4.5, which doesn't accept it.
- **Never truncates silently.** Documents over a 120,000-character budget show a
  warning and require an explicit toggle before the head of the file is sent.
- **Prompt injection.** Repository text is wrapped in `<document>` tags and the
  system prompt tells the model to treat it as untrusted data, not instructions.

## Key handling

The API key lives in the device keychain (`kSecAttrAccessibleAfterFirstUnlock`)
and is sent only to `api.anthropic.com`. That is fine for a personal experiment
and **not** how a shipping app should do it: anything on a device can eventually
be extracted, so a real app proxies these calls through a backend that holds the
key. The Settings screen says so too.

## Layout

```
PlaygroundCompanion/
├── PlaygroundCompanionApp.swift
├── Models/Experiment.swift          # experiments + GitHub contents decoding
├── Services/
│   ├── AppSettings.swift            # @AppStorage prefs + keychain-backed secrets
│   ├── ClaudeClient.swift           # Messages API, SSE streaming
│   ├── ExperimentStore.swift        # repo listing + root README table parsing
│   ├── GitHubClient.swift           # contents API, rate-limit aware
│   └── KeychainStore.swift
├── Markdown/                        # small block-level markdown parser + renderer
└── Views/                           # list, detail, browser, viewer, ask, settings
```

The Xcode project uses a file-system-synchronized root group, so adding a Swift
file to `PlaygroundCompanion/` picks it up automatically — no `project.pbxproj`
edit needed.

## Known gaps

- Never compiled (see above).
- No tests — a unit-test target would need a second target in the pbxproj, which
  seemed unwise to hand-write without a compiler to check it.
- The markdown renderer handles headings, paragraphs, fenced code, lists,
  blockquotes, tables, and rules. Nested lists, images, and footnotes are not
  handled.
- Conversation is single-turn: each question sends the document fresh rather
  than continuing a thread.
- The app icon is an empty placeholder slot.
