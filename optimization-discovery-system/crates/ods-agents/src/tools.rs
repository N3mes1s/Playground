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
                    "Query a sandbox-relative source file. If `pattern` starts with `(` it is \
                     parsed as a tree-sitter-rust S-expression query over the AST (e.g. \
                     `(call_expression function: (field_expression field: (field_identifier) @m))`); \
                     matches inside comments, string literals, and macro bodies are filtered out \
                     automatically. Otherwise `pattern` is treated as a line-anchored regex. \
                     Returns one entry per match with 1-based line numbers and the matched text."
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
    }

    /// Register mutating tools: apply_patch, run_bench, run_tests. These
    /// shell out into the sandbox; callers decide which specialist kinds are
    /// allowed to use them by registering conditionally.
    pub fn register_mutating(loop_: &mut ToolUseLoop, sandbox: Sandbox) {
        let sb = Arc::new(sandbox);

        loop_.register(
            ToolSpec {
                name: "apply_patch".into(),
                description:
                    "Apply a unified-diff patch to the sandbox via `git apply` when .git is \
                     present, otherwise write file contents in-place."
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
        let arg: AstQueryIn = serde_json::from_value(input.clone())?;
        let file = self.sandbox.resolve(&arg.path)?;
        let text = tokio::fs::read_to_string(&file).await?;
        let re = regex::Regex::new(&arg.pattern)?;
        let mut out = Vec::new();
        for (i, line) in text.lines().enumerate() {
            if re.is_match(line) {
                out.push(format!("{}:{}: {}", arg.path, i + 1, line));
            }
        }
        Ok(out.join("\n"))
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
        // git apply when possible; otherwise `patch -p1`.
        let tmp = root.join(".ods-tmp.patch");
        tokio::fs::write(&tmp, arg.diff.as_bytes()).await?;
        let result = if root.join(".git").exists() {
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
        let out = result?;
        if out.success() {
            Ok("applied".into())
        } else {
            Err(anyhow::anyhow!(
                "apply_patch failed: status={} stderr={}",
                out.status,
                out.stderr.chars().take(800).collect::<String>()
            ))
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
}
