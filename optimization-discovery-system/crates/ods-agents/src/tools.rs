//! Typed specialist tools.
//!
//! Every tool exposed to the LLM is a Rust function wrapped in a
//! [`ToolHandler`]. We keep the handlers deliberately simple and side-effect
//! scoped to an explicit [`Sandbox`] path so a specialist can't reach outside
//! its worktree.

use crate::anthropic::{ToolHandler, ToolSpec, ToolUseLoop};
use anyhow::Result;
use ods_core::TargetSig;
use ods_exec::{run, Invocation};
use ods_lang::{Build, LanguageAdapter, ProfileReport};
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

    /// Register mutating tools: edit_file, write_file, run_tests,
    /// run_bench. The agent never formats a unified diff — it edits
    /// files directly and the race captures the canonical patch via
    /// `git diff` after the conversation. That eliminates the entire
    /// class of malformed-patch failures we used to ship a fuzzy
    /// applier to work around.
    pub fn register_mutating(loop_: &mut ToolUseLoop, sandbox: Sandbox) {
        let sb = Arc::new(sandbox);

        loop_.register(
            ToolSpec {
                name: "edit_file".into(),
                description:
                    "Replace `old_string` with `new_string` in `path`. `old_string` must \
                     appear EXACTLY ONCE in the file (include enough surrounding context to \
                     make it unique). This is the primary mutation tool — the canonical diff \
                     is generated for you by git after the run. Use write_file when the \
                     change is large enough that a string replace becomes awkward."
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

    /// Register the `run_profile` tool. Profile invocations require a
    /// language adapter (to shell out to the right profiler pipeline) and
    /// the current target sig (the bench filter is derived from the
    /// target's `symbol`). Both are race-scoped, so we take them as
    /// arguments rather than embedding a registry. Explorer deliberately
    /// does not call this — a ~30-second profile per survey candidate
    /// would blow up its budget.
    pub fn register_profile(
        loop_: &mut ToolUseLoop,
        sandbox: Sandbox,
        adapter: Arc<dyn LanguageAdapter>,
        target: TargetSig,
    ) {
        let sb = Arc::new(sandbox);
        loop_.register(
            ToolSpec {
                name: "run_profile".into(),
                description:
                    "Profile the target under instrumentation (time, strace, perf stat) and \
                     return measured syscall counts, cycles/instructions, branch/LLC misses, \
                     and allocation totals. Call this BEFORE editing to see the baseline \
                     distribution of work, and AGAIN after your edit to verify the metric \
                     relevant to your specialist actually moved. If the relevant metric is \
                     not visibly hot in the baseline (e.g. no syscalls for a SyscallEliminator, \
                     low branch-misses for a FastPathSpecializer), abstain rather than apply \
                     the transform anyway. No arguments — the target sig is pinned for this \
                     race."
                        .into(),
                input_schema: serde_json::json!({
                    "type": "object",
                    "properties": {}
                }),
            },
            Box::new(RunProfile {
                sandbox: sb,
                adapter,
                target,
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

/// run_profile ------------------------------------------------------------
struct RunProfile {
    sandbox: Arc<Sandbox>,
    adapter: Arc<dyn LanguageAdapter>,
    target: TargetSig,
}
#[async_trait::async_trait]
impl ToolHandler for RunProfile {
    async fn call(&self, _input: &serde_json::Value) -> Result<String> {
        let build = Build {
            workdir: self.sandbox.root.clone(),
            artifact: None,
            toolchain: "stable".into(),
        };
        let report = self.adapter.profile(&build, &self.target).await?;
        Ok(format_profile_report(&report))
    }
}

/// Compact scannable header followed by pretty JSON. Missing metrics
/// render as `n/a` so partial profiling (e.g. `perf_event_paranoid=2`
/// blocks perf counters but `strace` still works) degrades gracefully
/// instead of erroring out the whole call.
fn format_profile_report(r: &ProfileReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("wall={:.3}s", r.wall.as_secs_f64()));
    s.push_str(&format!(
        "  cycles={}  instructions={}",
        fmt_count(r.cycles),
        fmt_count(r.instructions),
    ));
    s.push('\n');

    if r.syscall_counts.is_empty() {
        s.push_str("top syscalls: n/a (strace unavailable or bench never issued any)\n");
    } else {
        let mut sorted: Vec<_> = r.syscall_counts.iter().collect();
        sorted.sort_by(|a, b| b.1.cmp(&a.1));
        let preview: Vec<String> = sorted
            .iter()
            .take(8)
            .map(|(name, count)| format!("{name}={count}"))
            .collect();
        s.push_str(&format!("top syscalls: {}\n", preview.join(" ")));
    }

    s.push_str(&format!(
        "allocs: count={} bytes={}\n",
        fmt_count(r.alloc_count),
        fmt_count(r.alloc_bytes),
    ));
    s.push_str(&format!(
        "branch_misses={}  llc_misses={}\n",
        fmt_count(r.branch_misses),
        fmt_count(r.llc_misses),
    ));
    if let Some(p) = &r.flame_svg_path {
        s.push_str(&format!("flame svg: {}\n", p.display()));
    }

    s.push_str("\n---json---\n");
    match serde_json::to_string_pretty(r) {
        Ok(j) => s.push_str(&j),
        Err(_) => s.push_str("<json serialization failed>"),
    }
    s
}

fn fmt_count(v: Option<u64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "n/a".into(),
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
    use async_trait::async_trait;
    use ods_lang::{
        AstMatch, BenchReport, Edit as AdapterEdit, FuzzReport, Patch, TestReport, TestScope,
    };
    use std::time::Duration;

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

    struct StubAdapter {
        report: ProfileReport,
    }
    #[async_trait]
    impl LanguageAdapter for StubAdapter {
        fn name(&self) -> &'static str {
            "stub"
        }
        async fn detect(&self, _: &Path) -> Result<bool> {
            Ok(true)
        }
        async fn build(&self, p: &Path, _: Option<&Patch>) -> Result<Build> {
            Ok(Build {
                workdir: p.to_path_buf(),
                artifact: None,
                toolchain: "stub".into(),
            })
        }
        async fn run_tests(&self, _: &Build, _: TestScope) -> Result<TestReport> {
            Ok(TestReport {
                passed: 0,
                failed: 0,
                skipped: 0,
                log_path: None,
            })
        }
        async fn run_bench(&self, _: &Build, _: &TargetSig) -> Result<BenchReport> {
            Ok(BenchReport { samples: vec![] })
        }
        async fn profile(&self, _: &Build, _: &TargetSig) -> Result<ProfileReport> {
            Ok(self.report.clone())
        }
        async fn ast_query(&self, _: &Path, _: &str) -> Result<Vec<AstMatch>> {
            Ok(vec![])
        }
        fn emit_patch(&self, edits: &[AdapterEdit]) -> Result<Patch> {
            Ok(Patch {
                unified_diff: String::new(),
                edits: edits.to_vec(),
            })
        }
        async fn fuzz(&self, _: &Build, _: &TargetSig, _: Duration) -> Result<FuzzReport> {
            Ok(FuzzReport {
                minutes: 0,
                crashes: 0,
                seed_corpus_size: 0,
            })
        }
    }

    fn stub_target() -> TargetSig {
        TargetSig {
            language: "rust".into(),
            module: "m".into(),
            symbol: "s".into(),
            arity: None,
        }
    }

    #[tokio::test]
    async fn run_profile_emits_summary_header_and_json() {
        let tmp = tempfile::tempdir().unwrap();
        let report = ProfileReport {
            wall: Duration::from_millis(234),
            cycles: Some(87_000_000),
            instructions: Some(410_000_000),
            llc_misses: Some(4_800),
            branch_misses: Some(1_200_000),
            syscall_counts: vec![
                ("write".into(), 3421),
                ("read".into(), 891),
                ("openat".into(), 17),
            ],
            alloc_count: Some(1247),
            alloc_bytes: Some(312_000),
            flame_svg_path: None,
        };
        let tool = RunProfile {
            sandbox: Arc::new(Sandbox::new(tmp.path())),
            adapter: Arc::new(StubAdapter {
                report: report.clone(),
            }),
            target: stub_target(),
        };
        let out = tool.call(&serde_json::json!({})).await.unwrap();
        // Header should be compact + scannable, json payload should follow.
        assert!(out.starts_with("wall=0.234s"));
        assert!(out.contains("cycles=87000000"));
        // Syscalls sorted by count descending.
        assert!(out.contains("top syscalls: write=3421 read=891 openat=17"));
        assert!(out.contains("allocs: count=1247 bytes=312000"));
        assert!(out.contains("branch_misses=1200000"));
        assert!(out.contains("---json---"));
        // Round-trip the JSON half to confirm it parses.
        let (_hdr, json) = out.split_once("---json---").unwrap();
        let parsed: ProfileReport = serde_json::from_str(json.trim()).unwrap();
        assert_eq!(parsed.cycles, Some(87_000_000));
        assert_eq!(parsed.alloc_count, Some(1247));
    }

    #[tokio::test]
    async fn run_profile_renders_na_for_missing_metrics() {
        let tmp = tempfile::tempdir().unwrap();
        let report = ProfileReport {
            wall: Duration::from_millis(12),
            cycles: None,
            instructions: None,
            llc_misses: None,
            branch_misses: None,
            syscall_counts: vec![],
            alloc_count: None,
            alloc_bytes: None,
            flame_svg_path: None,
        };
        let tool = RunProfile {
            sandbox: Arc::new(Sandbox::new(tmp.path())),
            adapter: Arc::new(StubAdapter { report }),
            target: stub_target(),
        };
        let out = tool.call(&serde_json::json!({})).await.unwrap();
        assert!(out.contains("cycles=n/a"));
        assert!(out.contains("instructions=n/a"));
        assert!(out.contains("top syscalls: n/a"));
        assert!(out.contains("allocs: count=n/a bytes=n/a"));
        assert!(out.contains("branch_misses=n/a"));
        // Partial-data should not fail the call; only the metrics go n/a.
    }
}
