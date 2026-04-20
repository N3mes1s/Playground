//! Tolerant unified-diff applier for the `apply_patch` tool.
//!
//! Why this exists: the end-to-end run at `docs/first-end-to-end-win.md`
//! showed two of three specialists hitting `git apply` failures on
//! diffs the model generated. The two reproducible classes:
//!
//! 1. **Typographic context drift** — Anthropic models love to
//!    transcribe an em-dash (`—`) where the source has an ASCII
//!    hyphen, or curly quotes where the source has straight ones.
//!    `git apply --whitespace=fix` doesn't normalise these.
//! 2. **Hunk-header line-count drift** — the `@@ -L,N +L,N @@` claims
//!    say one thing, the body another. `git apply` rejects the whole
//!    hunk; a fuzzy applier just searches around the hint and applies
//!    where the pre-block actually matches.
//!
//! The strategy is: try `git apply` first (it's stricter and produces
//! perfect output when it succeeds), fall back to this fuzzy pass when
//! it doesn't. Operations limited to:
//! - Single-base unified-diff format (`---`/`+++`/`@@`).
//! - Modify-existing-file only (no rename, no delete, no new-file
//!   header — those go through `git apply` proper or fail loudly).
//! - One file per `--- a/path` … `+++ b/path` block, multiple hunks
//!   per file allowed.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ParsedDiff {
    pub files: Vec<FilePatch>,
}

#[derive(Debug, Clone)]
pub struct FilePatch {
    pub path: String,
    pub hunks: Vec<Hunk>,
}

#[derive(Debug, Clone)]
pub struct Hunk {
    /// 1-indexed line number from the `@@ -L,N` header. Used as a
    /// search hint; the actual application location can drift.
    pub pre_start_line: usize,
    /// Lines that should EXIST in the file before the patch is applied
    /// (context + removed). One String per source line, no trailing
    /// newline on each.
    pub pre_lines: Vec<String>,
    /// Lines that should EXIST in the file after (context + added).
    pub post_lines: Vec<String>,
}

/// Parse a unified diff into per-file hunk lists. Tolerant of:
/// - missing `a/` / `b/` prefixes
/// - extra header lines (`diff --git`, `index …`, `Binary files …`)
/// - the `\ No newline at end of file` marker (skipped)
pub fn parse_unified_diff(diff: &str) -> Result<ParsedDiff> {
    let mut files: Vec<FilePatch> = Vec::new();
    let mut current_file: Option<FilePatch> = None;
    let mut current_hunk: Option<Hunk> = None;
    let mut lines = diff.lines().peekable();

    while let Some(line) = lines.next() {
        if let Some(path) = line.strip_prefix("--- ") {
            // Flush prior hunk + file.
            if let Some(h) = current_hunk.take() {
                if let Some(f) = current_file.as_mut() {
                    f.hunks.push(h);
                }
            }
            if let Some(f) = current_file.take() {
                files.push(f);
            }
            // The `+++ ` line follows immediately. Read it for the
            // destination path; the `--- ` path is the source we
            // ignore (we modify-in-place using the `+++` path).
            let plus = lines.next().unwrap_or("");
            let plus_path = plus.strip_prefix("+++ ").unwrap_or(plus);
            let resolved = strip_diff_prefix(plus_path)
                .or_else(|| Some(strip_diff_prefix(path)?))
                .unwrap_or_else(|| plus_path.to_string());
            current_file = Some(FilePatch {
                path: resolved,
                hunks: Vec::new(),
            });
        } else if line.starts_with("@@") {
            if let Some(h) = current_hunk.take() {
                if let Some(f) = current_file.as_mut() {
                    f.hunks.push(h);
                }
            }
            let pre_start = parse_hunk_header(line).unwrap_or(1);
            current_hunk = Some(Hunk {
                pre_start_line: pre_start,
                pre_lines: Vec::new(),
                post_lines: Vec::new(),
            });
        } else if let Some(hunk) = current_hunk.as_mut() {
            // Hunk body lines.
            if line.starts_with("\\ ") {
                // "\ No newline at end of file" — skip.
                continue;
            }
            if let Some(body) = line.strip_prefix(' ') {
                hunk.pre_lines.push(body.to_string());
                hunk.post_lines.push(body.to_string());
            } else if let Some(body) = line.strip_prefix('-') {
                if !body.starts_with("-- ") {
                    // Avoid eating a stray `--` separator, which only
                    // appears at file boundaries; those went through
                    // the `--- ` arm above.
                    hunk.pre_lines.push(body.to_string());
                }
            } else if let Some(body) = line.strip_prefix('+') {
                if !body.starts_with("++ ") {
                    hunk.post_lines.push(body.to_string());
                }
            } else if line.is_empty() {
                // Empty body line is part of the hunk on both sides.
                hunk.pre_lines.push(String::new());
                hunk.post_lines.push(String::new());
            }
            // Other lines (`diff --git`, `index …`, mode bits) appear
            // BEFORE `--- ` and never inside a hunk; ignore here.
        }
    }
    if let Some(h) = current_hunk.take() {
        if let Some(f) = current_file.as_mut() {
            f.hunks.push(h);
        }
    }
    if let Some(f) = current_file.take() {
        files.push(f);
    }
    if files.is_empty() {
        anyhow::bail!("parse_unified_diff: no files in input");
    }
    Ok(ParsedDiff { files })
}

/// Apply a parsed diff to `repo` with fuzzy line-by-line matching.
/// Returns the number of hunks successfully applied.
pub fn apply_parsed_diff(repo: &Path, parsed: &ParsedDiff) -> Result<usize> {
    let mut applied = 0;
    for file in &parsed.files {
        let abs = repo.join(&file.path);
        let content =
            std::fs::read_to_string(&abs).with_context(|| format!("read {}", abs.display()))?;
        let trailing_newline = content.ends_with('\n');
        let mut lines: Vec<String> = if content.is_empty() {
            Vec::new()
        } else {
            content.lines().map(String::from).collect()
        };

        // Apply hunks in REVERSE order so prior hunks' line offsets
        // remain valid against the as-modified buffer.
        for hunk in file.hunks.iter().rev() {
            apply_hunk(&mut lines, hunk).with_context(|| {
                format!(
                    "hunk @@ -{},{} (in {}) failed to apply",
                    hunk.pre_start_line,
                    hunk.pre_lines.len(),
                    file.path,
                )
            })?;
            applied += 1;
        }

        let mut joined = lines.join("\n");
        if trailing_newline {
            joined.push('\n');
        }
        std::fs::write(&abs, joined).with_context(|| format!("write {}", abs.display()))?;
    }
    Ok(applied)
}

/// Convenience wrapper: parse + apply. If the input carries the
/// `*** Begin Patch / *** Update File:` envelope markers, translate
/// it into a standard unified diff first — that's the format frontier
/// LLMs default to when asked for "a patch" and historically blocked
/// us at apply_patch time.
pub fn apply_unified_diff(repo: &Path, diff: &str) -> Result<usize> {
    let translated;
    let effective: &str = if let Some(t) = translate_envelope_format(diff) {
        translated = t;
        &translated
    } else {
        diff
    };
    let parsed = parse_unified_diff(effective)?;
    if parsed.files.is_empty() {
        anyhow::bail!("parse_unified_diff: no files in input");
    }
    apply_parsed_diff(repo, &parsed)
}

/// Translate the `*** Begin Patch / *** Update File: <path>` envelope
/// format that LLMs frequently emit into a standard unified diff.
///
/// Input shape we accept:
/// ```text
/// *** Begin Patch
/// *** Update File: path/to/file.rs
/// @@ context anchor (optional, ignored)
///  context line
/// -removed line
/// +added line
/// *** End Patch
/// ```
///
/// Behaviour:
/// - `*** Update File: <path>` opens a file block (becomes `--- a/<path>` /
///   `+++ b/<path>` headers).
/// - `*** Add File: <path>` is treated like Update File: against an empty
///   pre-file (re-uses the pure-insertion hunk path).
/// - `*** Delete File: <path>` is intentionally NOT supported — file
///   removal should go through `git apply`.
/// - `*** Begin Patch` / `*** End Patch` are stripped.
/// - `@@` lines are kept as hunk headers but with a synthesised
///   `-1,N +1,N` range so the existing fuzzy applier's location search
///   takes over.
///
/// Returns `None` when the input doesn't look like an envelope, so the
/// caller can keep its original error message for unrelated parse
/// failures.
pub fn translate_envelope_format(input: &str) -> Option<String> {
    if !input.contains("*** Begin Patch") && !input.contains("*** Update File:") {
        return None;
    }
    let mut out = String::new();
    let mut in_file = false;
    let mut current_hunk_body: Vec<String> = Vec::new();
    let mut hunks_emitted_for_file = 0usize;

    let flush_hunk = |body: &mut Vec<String>, sink: &mut String, count: &mut usize| {
        if body.is_empty() {
            return;
        }
        let pre = body
            .iter()
            .filter(|l| !l.starts_with('+'))
            .count();
        let post = body
            .iter()
            .filter(|l| !l.starts_with('-'))
            .count();
        sink.push_str(&format!("@@ -1,{pre} +1,{post} @@\n"));
        for line in body.drain(..) {
            sink.push_str(&line);
            sink.push('\n');
        }
        *count += 1;
    };

    for raw in input.lines() {
        let line = raw;
        if line.starts_with("*** Begin Patch") || line.starts_with("*** End Patch") {
            continue;
        }
        if let Some(path) = line
            .strip_prefix("*** Update File: ")
            .or_else(|| line.strip_prefix("*** Add File: "))
        {
            // Close any prior file: flush the open hunk first.
            flush_hunk(&mut current_hunk_body, &mut out, &mut hunks_emitted_for_file);
            let path = path.trim();
            out.push_str(&format!("--- a/{path}\n+++ b/{path}\n"));
            in_file = true;
            hunks_emitted_for_file = 0;
            continue;
        }
        if line.starts_with("*** Delete File:") {
            // Not supported; let the caller fall through to a strict
            // applier that knows how to handle deletions properly.
            return None;
        }
        if !in_file {
            continue;
        }
        if line.starts_with("@@") {
            // Hunk boundary in the envelope. Flush whatever's queued.
            flush_hunk(&mut current_hunk_body, &mut out, &mut hunks_emitted_for_file);
            continue;
        }
        // Normal hunk body line. Lines without a leading +/-/space are
        // treated as context (envelope format is loose about that).
        let normalized = if line.starts_with('+') || line.starts_with('-') || line.starts_with(' ')
        {
            line.to_string()
        } else {
            format!(" {line}")
        };
        current_hunk_body.push(normalized);
    }
    flush_hunk(&mut current_hunk_body, &mut out, &mut hunks_emitted_for_file);

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

fn apply_hunk(lines: &mut Vec<String>, hunk: &Hunk) -> Result<()> {
    if hunk.pre_lines.is_empty() {
        // Pure-insertion hunk: place at the hint position.
        let pos = hunk.pre_start_line.saturating_sub(1).min(lines.len());
        for (i, l) in hunk.post_lines.iter().enumerate() {
            lines.insert(pos + i, l.clone());
        }
        return Ok(());
    }

    let n = hunk.pre_lines.len();
    if n > lines.len() {
        anyhow::bail!(
            "pre block needs {} lines but file has only {}",
            n,
            lines.len()
        );
    }
    let hint = hunk.pre_start_line.saturating_sub(1);

    // Search order: hint position first, then expanding outward.
    let last = lines.len() - n;
    let mut candidates: Vec<usize> = (0..=last).collect();
    candidates.sort_by_key(|&i| (i as i64 - hint as i64).abs());

    for start in candidates {
        if matches_loosely(&lines[start..start + n], &hunk.pre_lines) {
            // Reconstruct the output by walking post_lines and
            // distinguishing context (shared with pre, in order)
            // from added (post-only). Context lines come from DISK
            // verbatim — that's how we tolerate em-dash / curly-quote
            // drift in the model's diff context without rewriting the
            // user's actual file with the model's typographic
            // hallucinations.
            let pre = &hunk.pre_lines;
            let disk = &lines[start..start + n];
            let mut new_block: Vec<String> = Vec::with_capacity(hunk.post_lines.len());
            let mut pre_idx = 0;
            for post_line in &hunk.post_lines {
                // Look ahead in pre for a loose match for this post line.
                let mut probe = pre_idx;
                while probe < pre.len()
                    && normalise_for_match(post_line) != normalise_for_match(&pre[probe])
                {
                    probe += 1;
                }
                if probe < pre.len() {
                    // Context: use disk's actual line, advance past
                    // any pre lines we skipped (they were removals).
                    new_block.push(disk[probe].clone());
                    pre_idx = probe + 1;
                } else {
                    // No match in remaining pre → this is an addition.
                    new_block.push(post_line.clone());
                }
            }
            lines.splice(start..start + n, new_block);
            return Ok(());
        }
    }
    anyhow::bail!(
        "pre block of {} lines not found in file (hint was line {})",
        n,
        hunk.pre_start_line
    );
}

fn matches_loosely(actual: &[String], expected: &[String]) -> bool {
    if actual.len() != expected.len() {
        return false;
    }
    actual
        .iter()
        .zip(expected.iter())
        .all(|(a, e)| normalise_for_match(a) == normalise_for_match(e))
}

/// Normalisation for matching context + removed lines. Strips trailing
/// whitespace, replaces common Unicode typographic substitutions with
/// their ASCII equivalents (the model's pet failure mode), and collapses
/// runs of internal whitespace to a single space. Add-side lines are
/// NOT normalised — they go in verbatim.
fn normalise_for_match(s: &str) -> String {
    let trimmed = s.trim_end();
    let mut out = String::with_capacity(trimmed.len());
    let mut last_was_ws = false;
    for ch in trimmed.chars() {
        let canonical = match ch {
            '—' | '–' | '−' => '-',
            '\u{2018}' | '\u{2019}' | '\u{02BC}' => '\'',
            '\u{201C}' | '\u{201D}' => '"',
            '\u{00A0}' => ' ',
            _ => ch,
        };
        if canonical.is_whitespace() {
            if !last_was_ws {
                out.push(' ');
            }
            last_was_ws = true;
        } else {
            out.push(canonical);
            last_was_ws = false;
        }
    }
    out.trim().to_string()
}

fn strip_diff_prefix(p: &str) -> Option<String> {
    let p = p.trim();
    let p = p.split_whitespace().next().unwrap_or(p);
    if let Some(rest) = p.strip_prefix("a/") {
        return Some(rest.to_string());
    }
    if let Some(rest) = p.strip_prefix("b/") {
        return Some(rest.to_string());
    }
    if p == "/dev/null" {
        return None;
    }
    Some(p.to_string())
}

fn parse_hunk_header(line: &str) -> Option<usize> {
    // `@@ -L[,N] +L[,N] @@ optional_context`
    let after_minus = line.split_once('-')?.1;
    let nums = after_minus.split_whitespace().next()?;
    let first = nums.split(',').next()?;
    first.parse().ok()
}

#[allow(dead_code)]
pub(crate) fn _unused_path_silence(_p: &Path) -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test diffs use explicit `\n` rather than Rust's `\` line
    // continuation, which would eat the leading-space context marker
    // and corrupt the test (cost me 30 minutes the first time).
    fn join(lines: &[&str]) -> String {
        let mut s = String::new();
        for l in lines {
            s.push_str(l);
            s.push('\n');
        }
        s
    }

    #[test]
    fn parses_single_file_single_hunk() {
        let diff = join(&[
            "--- a/src/lib.rs",
            "+++ b/src/lib.rs",
            "@@ -1,3 +1,3 @@",
            " fn main() {",
            "-    println!(\"hi\");",
            "+    println!(\"hello\");",
            " }",
        ]);
        let p = parse_unified_diff(&diff).unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.files[0].path, "src/lib.rs");
        assert_eq!(p.files[0].hunks.len(), 1);
        let h = &p.files[0].hunks[0];
        assert_eq!(h.pre_start_line, 1);
        assert_eq!(h.pre_lines.len(), 3);
        assert_eq!(h.post_lines.len(), 3);
        assert_eq!(h.pre_lines[1], "    println!(\"hi\");");
        assert_eq!(h.post_lines[1], "    println!(\"hello\");");
    }

    #[test]
    fn applies_em_dash_drift() {
        // The MODEL'S diff has an em-dash in the context; the actual
        // file has an ASCII hyphen. `git apply` would reject; the
        // fuzzy applier normalises and matches.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("x.rs");
        std::fs::write(
            &p,
            "/// before - some text\nlet mut out = Vec::new();\nout.push(0);\n",
        )
        .unwrap();
        let diff = join(&[
            "--- a/x.rs",
            "+++ b/x.rs",
            "@@ -1,3 +1,3 @@",
            " /// before — some text",
            "-let mut out = Vec::new();",
            "+let mut out = Vec::with_capacity(64);",
            " out.push(0);",
        ]);
        let n = apply_unified_diff(dir.path(), &diff).unwrap();
        assert_eq!(n, 1);
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(
            after.contains("Vec::with_capacity(64)"),
            "patched content missing: {after}"
        );
        assert!(
            after.contains("/// before - some text"),
            "context line should be unchanged from disk: {after}"
        );
    }

    #[test]
    fn applies_hunk_with_drifted_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("y.rs");
        std::fs::write(
            &p,
            "// preamble\n// preamble\n// preamble\n// preamble\n// preamble\n\
fn main() {\n    println!(\"hi\");\n}\n",
        )
        .unwrap();
        let diff = join(&[
            "--- a/y.rs",
            "+++ b/y.rs",
            "@@ -1,3 +1,3 @@",
            " fn main() {",
            "-    println!(\"hi\");",
            "+    println!(\"hello\");",
            " }",
        ]);
        let n = apply_unified_diff(dir.path(), &diff).unwrap();
        assert_eq!(n, 1);
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("println!(\"hello\")"));
        assert!(after.contains("// preamble"));
    }

    #[test]
    fn applies_two_hunks_in_one_file() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("z.rs");
        std::fs::write(
            &p,
            "fn a() { 1 }\nfn b() { 2 }\nfn c() { 3 }\nfn d() { 4 }\nfn e() { 5 }\n",
        )
        .unwrap();
        let diff = join(&[
            "--- a/z.rs",
            "+++ b/z.rs",
            "@@ -1,1 +1,1 @@",
            "-fn a() { 1 }",
            "+fn a() { 11 }",
            "@@ -5,1 +5,1 @@",
            "-fn e() { 5 }",
            "+fn e() { 55 }",
        ]);
        let n = apply_unified_diff(dir.path(), &diff).unwrap();
        assert_eq!(n, 2);
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("fn a() { 11 }"));
        assert!(after.contains("fn e() { 55 }"));
        assert!(after.contains("fn b() { 2 }"));
    }

    #[test]
    fn fails_loudly_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("w.rs");
        std::fs::write(&p, "totally unrelated content\n").unwrap();
        let diff = join(&[
            "--- a/w.rs",
            "+++ b/w.rs",
            "@@ -1,1 +1,1 @@",
            "-let x = 1;",
            "+let x = 2;",
        ]);
        let err = apply_unified_diff(dir.path(), &diff).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("hunk"), "expected helpful err, got {msg}");
    }

    #[test]
    fn parses_diff_with_git_header_lines() {
        let diff = join(&[
            "diff --git a/foo b/foo",
            "index 1234..5678 100644",
            "--- a/foo",
            "+++ b/foo",
            "@@ -1,1 +1,1 @@",
            "-old",
            "+new",
        ]);
        let p = parse_unified_diff(&diff).unwrap();
        assert_eq!(p.files.len(), 1);
        assert_eq!(p.files[0].path, "foo");
    }

    /// The `*** Begin Patch / *** Update File:` envelope is what
    /// frontier models default to when asked for "a patch". We
    /// translate it into a unified diff so apply_patch accepts it
    /// transparently.
    #[test]
    fn translates_openai_envelope_format() {
        // NOTE: line continuations (`\`) eat leading whitespace in Rust
        // string literals — that's exactly the bug we hit with the
        // divan parser. Build the input via explicit newline join.
        let envelope = join(&[
            "*** Begin Patch",
            "*** Update File: src/lib.rs",
            "@@",
            " fn keep() {}",
            "-fn old() {}",
            "+fn new() {}",
            "*** End Patch",
        ]);
        let translated = translate_envelope_format(&envelope).expect("envelope detected");
        let parsed = parse_unified_diff(&translated).unwrap();
        assert_eq!(parsed.files.len(), 1);
        assert_eq!(parsed.files[0].path, "src/lib.rs");
        let h = &parsed.files[0].hunks[0];
        assert_eq!(h.pre_lines, vec!["fn keep() {}", "fn old() {}"]);
        assert_eq!(h.post_lines, vec!["fn keep() {}", "fn new() {}"]);
    }

    #[test]
    fn apply_unified_diff_accepts_envelope_via_translator() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("src/lib.rs");
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(&p, "fn keep() {}\nfn old() {}\n").unwrap();
        let envelope = join(&[
            "*** Begin Patch",
            "*** Update File: src/lib.rs",
            "@@",
            " fn keep() {}",
            "-fn old() {}",
            "+fn new() {}",
            "*** End Patch",
        ]);
        let n = apply_unified_diff(dir.path(), &envelope).unwrap();
        assert_eq!(n, 1);
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("fn new() {}"));
        assert!(!after.contains("fn old() {}"));
    }

    #[test]
    fn envelope_translator_returns_none_for_plain_unified_diff() {
        let plain = join(&["--- a/x", "+++ b/x", "@@ -1,1 +1,1 @@", "-a", "+b"]);
        assert!(translate_envelope_format(&plain).is_none());
    }
}
