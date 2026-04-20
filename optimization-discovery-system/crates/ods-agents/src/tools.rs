//! Typed specialist tools.
//!
//! Every tool exposed to the LLM is a Rust function wrapped in a
//! [`ToolHandler`]. We keep the handlers deliberately simple and side-effect
//! scoped to an explicit [`Sandbox`] path so a specialist can't reach outside
//! its worktree.

use crate::anthropic::{ToolHandler, ToolSpec, ToolUseLoop};
use anyhow::Result;
use ods_exec::{run, Invocation};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Bundle of tool specs + handlers that a specialist is allowed to call.
pub struct SpecialistToolkit {
    pub sandbox: Sandbox,
}

#[derive(Debug, Clone)]
pub struct Sandbox {
    pub root: PathBuf,
}

impl Sandbox {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn resolve(&self, rel: &str) -> Result<PathBuf> {
        let p = self.root.join(rel);
        // Lexical normalisation is sufficient because we never want to rely
        // on disk state for enforcement. `..` components that would escape
        // the sandbox root are rejected regardless of whether the target
        // exists.
        let normalized = normalize(&p);
        let root = normalize(&self.root);
        if !normalized.starts_with(&root) {
            anyhow::bail!("path {} escapes sandbox", rel);
        }
        Ok(normalized)
    }
}

fn normalize(p: &Path) -> PathBuf {
    let mut out: Vec<std::path::Component<'_>> = Vec::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                if !matches!(
                    out.last(),
                    Some(std::path::Component::RootDir)
                        | Some(std::path::Component::Prefix(_))
                        | None
                ) {
                    out.pop();
                } else if out.is_empty() {
                    // leading .. with no root: represent escape explicitly
                    out.push(c);
                }
            }
            std::path::Component::CurDir => {}
            _ => out.push(c),
        }
    }
    out.iter().collect()
}

pub struct ToolHandlerMap;

impl ToolHandlerMap {
    /// Register the default read-only analysis toolkit (read_file, ast_query,
    /// list_dir) onto an existing [`ToolUseLoop`].
    pub fn register_read_only(loop_: &mut ToolUseLoop, sandbox: Sandbox) {
        let sb = Arc::new(sandbox);

        loop_.register(
            ToolSpec {
                name: "read_file".into(),
                description: "Read a UTF-8 text file from the sandbox at the given relative path."
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" }
                    },
                    "required": ["path"]
                }),
            },
            Box::new(ReadFile {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "list_dir".into(),
                description: "List entries in a directory relative to the sandbox.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "path": { "type": "string" } },
                    "required": ["path"]
                }),
            },
            Box::new(ListDir {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "ast_query".into(),
                description:
                    "Query a sandbox-relative source file with a tree-sitter S-expression over \
                     the parsed AST. Example: \
                     `(call_expression function: (field_expression field: (field_identifier) @m))`. \
                     Matches inside comments, string literals, and macro bodies are filtered out \
                     by the grammar. Every pattern MUST include at least one named capture \
                     (`@name`) — the tool returns one entry per captured node with 1-based line \
                     numbers and the node's source text. Grammar is selected from the file \
                     extension (rust, python, go)."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "pattern": { "type": "string" }
                    },
                    "required": ["path", "pattern"]
                }),
            },
            Box::new(AstQuery { sandbox: sb.clone() }),
        );

        loop_.register(
            ToolSpec {
                name: "ast_query_batch".into(),
                description:
                    "Run several tree-sitter queries against the SAME file in one call. Same \
                     semantics as `ast_query` per individual pattern, but parses the file once \
                     and returns a structured list of hits per pattern. Use this when you want \
                     to probe multiple shapes in one source file (e.g. `for x in y.clone()` AND \
                     `format!()` AND `Vec::new()`) without paying N LLM turns. Every pattern \
                     MUST include at least one `@capture`. Output shape: one section per \
                     pattern, labelled `# pattern N: …` with its hits underneath."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "patterns": {
                            "type": "array",
                            "items": { "type": "string" },
                            "minItems": 1,
                            "maxItems": 16
                        }
                    },
                    "required": ["path", "patterns"]
                }),
            },
            Box::new(AstQueryBatch {
                sandbox: sb.clone(),
            }),
        );
    }

    /// Register mutating tools: apply_patch, run_bench, run_tests. These
    /// shell out into the sandbox; callers decide which specialist kinds are
    /// allowed to use them by registering conditionally.
    pub fn register_mutating(loop_: &mut ToolUseLoop, sandbox: Sandbox) {
        let sb = Arc::new(sandbox);

        // edit_file is the PRIMARY mutation tool. It does in-place
        // string replacement and returns a small diff preview so the
        // agent can confirm the edit landed where it expected. We
        // capture the canonical patch via `git diff` after the
        // conversation ends, so the agent never has to format a
        // unified diff itself — the most common cause of historic
        // apply_patch failures.
        loop_.register(
            ToolSpec {
                name: "edit_file".into(),
                description:
                    "Replace `old_string` with `new_string` in `path`. `old_string` must \
                     appear EXACTLY ONCE in the file (include enough surrounding context to \
                     make it unique). PREFER this over apply_patch: it is faster, cheaper, \
                     and the canonical diff is generated for you by git after the run. Use \
                     write_file when the change is large enough that a string replace becomes \
                     awkward."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "old_string": { "type": "string" },
                        "new_string": { "type": "string" }
                    },
                    "required": ["path", "old_string", "new_string"]
                }),
            },
            Box::new(EditFile {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "write_file".into(),
                description:
                    "Overwrite `path` with `content`. Creates the file if it does not exist. \
                     Use for large rewrites or new files; prefer edit_file for surgical \
                     changes."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {
                        "path": { "type": "string" },
                        "content": { "type": "string" }
                    },
                    "required": ["path", "content"]
                }),
            },
            Box::new(WriteFile {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "apply_patch".into(),
                description:
                    "Apply a patch to the sandbox. Accepts unified diff (preferred) OR the \
                     `*** Begin Patch / *** Update File: <path>` envelope format. PREFER \
                     edit_file or write_file for new changes — the diff is generated by git \
                     for you and it eliminates an entire class of patch-format failures."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "diff": { "type": "string" } },
                    "required": ["diff"]
                }),
            },
            Box::new(ApplyPatch {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "run_tests".into(),
                description: "Run the sandbox's test suite and return a structured summary.".into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "language": { "type": "string" } },
                    "required": ["language"]
                }),
            },
            Box::new(RunTests {
                sandbox: sb.clone(),
            }),
        );

        loop_.register(
            ToolSpec {
                name: "run_bench".into(),
                description: "Run the sandbox's bench suite; returns parsed ns/iter per sample."
                    .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": { "filter": { "type": "string" } }
                }),
            },
            Box::new(RunBench {
                sandbox: sb.clone(),
            }),
        );
    }
}

/// read_file --------------------------------------------------------------
struct ReadFile {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct ReadFileIn {
    path: String,
}
#[async_trait::async_trait]
impl ToolHandler for ReadFile {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: ReadFileIn = serde_json::from_value(input.clone())?;
        let path = self.sandbox.resolve(&arg.path)?;
        Ok(tokio::fs::read_to_string(&path).await?)
    }
}

/// list_dir ---------------------------------------------------------------
struct ListDir {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct ListDirIn {
    path: String,
}
#[async_trait::async_trait]
impl ToolHandler for ListDir {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: ListDirIn = serde_json::from_value(input.clone())?;
        let path = self.sandbox.resolve(&arg.path)?;
        let mut entries: Vec<String> = Vec::new();
        for e in std::fs::read_dir(&path)? {
            let e = e?;
            let name = e.file_name().to_string_lossy().into_owned();
            let kind = if e.file_type()?.is_dir() { "d" } else { "f" };
            entries.push(format!("{kind} {name}"));
        }
        entries.sort();
        Ok(entries.join("\n"))
    }
}

/// ast_query --------------------------------------------------------------
struct AstQuery {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct AstQueryIn {
    path: String,
    pattern: String,
}
#[async_trait::async_trait]
impl ToolHandler for AstQuery {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        use ods_lang::LanguageAdapter;
        let arg: AstQueryIn = serde_json::from_value(input.clone())?;
        let file = self.sandbox.resolve(&arg.path)?;
        // Dispatch to the right language adapter by file extension. This
        // is the same set the Discoverer supports.
        let adapter: Box<dyn LanguageAdapter> = match file.extension().and_then(|s| s.to_str()) {
            Some("rs") => Box::new(ods_lang_rust::RustAdapter::new()),
            Some("py") => Box::new(ods_lang_python::PythonAdapter::new()),
            Some("go") => Box::new(ods_lang_go::GoAdapter::new()),
            Some("rb") => Box::new(ods_lang_ruby::RubyAdapter::new()),
            other => {
                anyhow::bail!(
                    "ast_query: no tree-sitter grammar for extension {other:?}; \
                     supported: .rs / .py / .go / .rb"
                );
            }
        };
        let hits = adapter.ast_query(&file, &arg.pattern).await?;
        if hits.is_empty() {
            return Ok("no matches".into());
        }
        // Surface (path, line range, enclosing fn, matched text) so the
        // agent can point a follow-up tool call (read_file) at a precise
        // location instead of scanning the whole file by hand.
        let mut lines = Vec::with_capacity(hits.len());
        for h in hits.iter().take(50) {
            let loc = if let Some(sym) = &h.enclosing_symbol {
                format!("{}:{}-{} (in fn {sym})", arg.path, h.start_line, h.end_line)
            } else {
                format!("{}:{}-{}", arg.path, h.start_line, h.end_line)
            };
            // Inline text is one line of preview to keep the tool output
            // scannable; agents can always read_file for context.
            let preview = h.text.lines().next().unwrap_or("").trim();
            lines.push(format!("{loc}: {preview}"));
        }
        if hits.len() > 50 {
            lines.push(format!("… and {} more hits", hits.len() - 50));
        }
        Ok(lines.join("\n"))
    }
}

/// ast_query_batch --------------------------------------------------------
struct AstQueryBatch {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct AstQueryBatchIn {
    path: String,
    patterns: Vec<String>,
}
#[async_trait::async_trait]
impl ToolHandler for AstQueryBatch {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        use ods_lang::LanguageAdapter;
        let arg: AstQueryBatchIn = serde_json::from_value(input.clone())?;
        if arg.patterns.is_empty() {
            anyhow::bail!("ast_query_batch: `patterns` must contain at least one query");
        }
        let file = self.sandbox.resolve(&arg.path)?;
        let adapter: Box<dyn LanguageAdapter> = match file.extension().and_then(|s| s.to_str()) {
            Some("rs") => Box::new(ods_lang_rust::RustAdapter::new()),
            Some("py") => Box::new(ods_lang_python::PythonAdapter::new()),
            Some("go") => Box::new(ods_lang_go::GoAdapter::new()),
            Some("rb") => Box::new(ods_lang_ruby::RubyAdapter::new()),
            other => {
                anyhow::bail!(
                    "ast_query_batch: no tree-sitter grammar for extension {other:?}; \
                     supported: .rs / .py / .go / .rb"
                );
            }
        };
        let pattern_refs: Vec<&str> = arg.patterns.iter().map(|s| s.as_str()).collect();
        let results = adapter.ast_query_batch(&file, &pattern_refs).await?;

        let mut out = String::new();
        for (idx, (pattern, hits)) in arg.patterns.iter().zip(results.iter()).enumerate() {
            if idx > 0 {
                out.push_str("\n\n");
            }
            // One-line header with a preview of the pattern so the agent
            // can correlate each section back to its input.
            let preview = pattern
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .take(1)
                .collect::<Vec<_>>()
                .join(" ");
            let preview_short: String = preview.chars().take(100).collect();
            out.push_str(&format!("# pattern {}: {preview_short}\n", idx + 1));
            if hits.is_empty() {
                out.push_str("  no matches");
                continue;
            }
            for h in hits.iter().take(50) {
                let loc = if let Some(sym) = &h.enclosing_symbol {
                    format!("{}:{}-{} (in fn {sym})", arg.path, h.start_line, h.end_line)
                } else {
                    format!("{}:{}-{}", arg.path, h.start_line, h.end_line)
                };
                let preview = h.text.lines().next().unwrap_or("").trim();
                out.push_str(&format!("  {loc}: {preview}\n"));
            }
            if hits.len() > 50 {
                out.push_str(&format!("  … and {} more hits\n", hits.len() - 50));
            }
        }
        Ok(out)
    }
}

/// edit_file --------------------------------------------------------------
/// In-place string replacement. The agent is expected to include enough
/// surrounding context in `old_string` to make it unique within the
/// file; we reject the call if it appears 0 or >1 times so a typo
/// can't silently mass-rewrite the wrong lines. After the conversation
/// ends, `git diff` in the worktree produces the canonical patch.
struct EditFile {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct EditFileIn {
    path: String,
    old_string: String,
    new_string: String,
}
#[async_trait::async_trait]
impl ToolHandler for EditFile {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: EditFileIn = serde_json::from_value(input.clone())?;
        let path = self.sandbox.resolve(&arg.path)?;
        let original = tokio::fs::read_to_string(&path).await?;
        let count = original.matches(&arg.old_string).count();
        if count == 0 {
            anyhow::bail!(
                "edit_file: `old_string` not found in {} — include enough context to match \
                 verbatim, or call read_file first to confirm the exact text",
                arg.path
            );
        }
        if count > 1 {
            anyhow::bail!(
                "edit_file: `old_string` matches {count} locations in {} — add more \
                 surrounding context so the match is unique",
                arg.path
            );
        }
        let updated = original.replacen(&arg.old_string, &arg.new_string, 1);
        tokio::fs::write(&path, updated.as_bytes()).await?;
        // A short scannable receipt — line count delta + the first
        // changed line. Keeps the assistant's context cheap.
        let before_lines = arg.old_string.lines().count();
        let after_lines = arg.new_string.lines().count();
        let first_changed = arg
            .new_string
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(120)
            .collect::<String>();
        Ok(format!(
            "edited {}: {before_lines} line(s) -> {after_lines} line(s); first new line: {first_changed}",
            arg.path
        ))
    }
}

/// write_file -------------------------------------------------------------
struct WriteFile {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct WriteFileIn {
    path: String,
    content: String,
}
#[async_trait::async_trait]
impl ToolHandler for WriteFile {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: WriteFileIn = serde_json::from_value(input.clone())?;
        let path = self.sandbox.resolve(&arg.path)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, arg.content.as_bytes()).await?;
        Ok(format!(
            "wrote {} ({} bytes)",
            arg.path,
            arg.content.len()
        ))
    }
}

/// apply_patch ------------------------------------------------------------
struct ApplyPatch {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct ApplyPatchIn {
    diff: String,
}
#[async_trait::async_trait]
impl ToolHandler for ApplyPatch {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: ApplyPatchIn = serde_json::from_value(input.clone())?;
        let root: &Path = &self.sandbox.root;

        // Two-stage application:
        //
        // 1. Try `git apply` (or `patch -p1`) — strict, perfect output
        //    when it succeeds, but rejects any context drift.
        // 2. On failure, fall back to the in-process tolerant applier
        //    in `crate::diff_apply` which normalises typographic chars
        //    (em-dash → hyphen, curly quotes → straight) and searches
        //    around the hunk-header line hint. Documented in
        //    `docs/first-end-to-end-win.md` as the top observed
        //    failure mode for specialist-generated diffs.
        let tmp = root.join(".ods-tmp.patch");
        tokio::fs::write(&tmp, arg.diff.as_bytes()).await?;
        let strict_result = if root.join(".git").exists() {
            run(&Invocation::new("git")
                .args([
                    "apply".to_string(),
                    "--reject".to_string(),
                    "--whitespace=fix".to_string(),
                    tmp.display().to_string(),
                ])
                .cwd(root)
                .allow_nonzero())
            .await
        } else {
            run(&Invocation::new("patch")
                .args([
                    "-p1".to_string(),
                    "-i".to_string(),
                    tmp.display().to_string(),
                ])
                .cwd(root)
                .allow_nonzero())
            .await
        };
        let _ = tokio::fs::remove_file(&tmp).await;

        match strict_result {
            Ok(out) if out.success() => Ok("applied (strict)".into()),
            Ok(out) => {
                let strict_stderr = out.stderr.chars().take(400).collect::<String>();
                match crate::diff_apply::apply_unified_diff(root, &arg.diff) {
                    Ok(n) => Ok(format!(
                        "applied ({n} hunks via fuzzy fallback after git/patch rejected)"
                    )),
                    Err(fuzzy_err) => Err(anyhow::anyhow!(
                        "apply_patch failed: strict status={} ({strict_stderr}); fuzzy fallback: {fuzzy_err:#}",
                        out.status,
                    )),
                }
            }
            Err(strict_err) => {
                // Strict tool wasn't even runnable (no git, no patch).
                // The fuzzy applier is self-contained — give it a try.
                match crate::diff_apply::apply_unified_diff(root, &arg.diff) {
                    Ok(n) => Ok(format!(
                        "applied ({n} hunks via fuzzy fallback; strict tool unavailable)"
                    )),
                    Err(fuzzy_err) => Err(anyhow::anyhow!(
                        "apply_patch failed: strict tool errored ({strict_err:#}); \
                         fuzzy fallback: {fuzzy_err:#}"
                    )),
                }
            }
        }
    }
}

/// run_tests --------------------------------------------------------------
struct RunTests {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct RunTestsIn {
    language: String,
}
#[async_trait::async_trait]
impl ToolHandler for RunTests {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: RunTestsIn = serde_json::from_value(input.clone())?;
        let root: &Path = &self.sandbox.root;
        let (program, args): (&str, Vec<String>) = match arg.language.as_str() {
            "rust" => (
                "cargo",
                vec![
                    "test".into(),
                    "--workspace".into(),
                    "--no-fail-fast".into(),
                    "--quiet".into(),
                ],
            ),
            "go" => ("go", vec!["test".into(), "./...".into()]),
            "python" => ("pytest", vec!["-q".into()]),
            "ruby" => ("rake", vec!["test".into()]),
            "javascript" | "js" | "typescript" | "ts" => {
                ("npm", vec!["test".into(), "--silent".into()])
            }
            "c" | "cpp" | "c++" => ("ctest", vec!["--output-on-failure".into()]),
            "java" => ("mvn", vec!["-q".into(), "test".into()]),
            _ => anyhow::bail!("unsupported language {}", arg.language),
        };
        let out = run(&Invocation::new(program)
            .args(args)
            .cwd(root)
            .allow_nonzero())
        .await?;
        Ok(format!(
            "status={}\n---stdout---\n{}\n---stderr---\n{}",
            out.status,
            truncate(&out.stdout, 4000),
            truncate(&out.stderr, 4000)
        ))
    }
}

/// run_bench --------------------------------------------------------------
struct RunBench {
    sandbox: Arc<Sandbox>,
}
#[derive(Deserialize)]
struct RunBenchIn {
    #[serde(default)]
    filter: Option<String>,
}
#[async_trait::async_trait]
impl ToolHandler for RunBench {
    async fn call(&self, input: &serde_json::Value) -> Result<String> {
        let arg: RunBenchIn = serde_json::from_value(input.clone())?;
        let root: &Path = &self.sandbox.root;
        let mut args: Vec<String> = vec!["bench".into(), "--workspace".into()];
        if let Some(f) = arg.filter {
            args.push("--".into());
            args.push(f);
        }
        let out = run(&Invocation::new("cargo")
            .args(args)
            .cwd(root)
            .allow_nonzero())
        .await?;
        Ok(format!(
            "status={}\n---stdout---\n{}",
            out.status,
            truncate(&out.stdout, 8000)
        ))
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}\n[...{} bytes truncated]", &s[..n], s.len() - n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_rejects_parent_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let sb = Sandbox::new(tmp.path());
        assert!(sb.resolve("../etc/passwd").is_err());
    }

    #[tokio::test]
    async fn edit_file_replaces_unique_match() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("a.txt");
        std::fs::write(&f, "alpha\nbeta\ngamma\n").unwrap();
        let sb = Arc::new(Sandbox::new(tmp.path()));
        let tool = EditFile {
            sandbox: sb.clone(),
        };
        let r = tool
            .call(&serde_json::json!({
                "path": "a.txt",
                "old_string": "beta",
                "new_string": "BETA"
            }))
            .await
            .unwrap();
        assert!(r.contains("edited a.txt"));
        let on_disk = std::fs::read_to_string(&f).unwrap();
        assert_eq!(on_disk, "alpha\nBETA\ngamma\n");
    }

    #[tokio::test]
    async fn edit_file_rejects_zero_matches() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "alpha\n").unwrap();
        let sb = Arc::new(Sandbox::new(tmp.path()));
        let tool = EditFile { sandbox: sb };
        let err = tool
            .call(&serde_json::json!({
                "path": "a.txt",
                "old_string": "missing",
                "new_string": "X"
            }))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("not found"));
    }

    #[tokio::test]
    async fn edit_file_rejects_ambiguous_match() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.txt"), "x\nx\n").unwrap();
        let sb = Arc::new(Sandbox::new(tmp.path()));
        let tool = EditFile { sandbox: sb };
        let err = tool
            .call(&serde_json::json!({
                "path": "a.txt",
                "old_string": "x",
                "new_string": "Y"
            }))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("matches 2 locations"));
    }

    #[tokio::test]
    async fn write_file_creates_nested_path() {
        let tmp = tempfile::tempdir().unwrap();
        let sb = Arc::new(Sandbox::new(tmp.path()));
        let tool = WriteFile { sandbox: sb };
        tool.call(&serde_json::json!({
            "path": "sub/dir/new.rs",
            "content": "fn x() {}\n"
        }))
        .await
        .unwrap();
        let on_disk = std::fs::read_to_string(tmp.path().join("sub/dir/new.rs")).unwrap();
        assert_eq!(on_disk, "fn x() {}\n");
    }
}
