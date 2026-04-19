//! Git worktree helpers. Specialists race in parallel copies of the target
//! repo; we represent each copy as a [`Worktree`]. The implementation shells
//! out to `git` to avoid linking libgit2 / openssl into the binary.
//!
//! Non-git repositories fall back to a plain directory copy via
//! [`Worktree::from_copy`].

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// A handle to a per-specialist worktree. On drop, the worktree is cleaned
/// up. A run ID prefix is embedded into the path so parallel specialists
/// don't collide.
pub struct WorktreeHandle {
    pub path: PathBuf,
    pub cleanup: Option<CleanupMode>,
}

#[derive(Debug, Clone)]
pub enum CleanupMode {
    GitWorktreeRemove { source: PathBuf },
    RemoveDir,
    Keep,
}

impl Drop for WorktreeHandle {
    fn drop(&mut self) {
        let Some(mode) = self.cleanup.take() else {
            return;
        };
        match mode {
            CleanupMode::GitWorktreeRemove { source } => {
                let _ = Command::new("git")
                    .arg("-C")
                    .arg(&source)
                    .arg("worktree")
                    .arg("remove")
                    .arg("--force")
                    .arg(&self.path)
                    .status();
            }
            CleanupMode::RemoveDir => {
                let _ = std::fs::remove_dir_all(&self.path);
            }
            CleanupMode::Keep => {}
        }
    }
}

pub struct Worktree;

impl Worktree {
    /// Create a worktree off `source`. When the source is a git checkout we
    /// use `git worktree add --detach`; otherwise we copy the directory.
    pub fn create(source: &Path, tag: &str, parent: &Path) -> Result<WorktreeHandle> {
        std::fs::create_dir_all(parent)?;
        let target = parent.join(format!("ods-{}", sanitize(tag)));
        if target.exists() {
            std::fs::remove_dir_all(&target)?;
        }
        if is_git(source) {
            let status = Command::new("git")
                .arg("-C")
                .arg(source)
                .arg("worktree")
                .arg("add")
                .arg("--detach")
                .arg(&target)
                .status()
                .context("git worktree add")?;
            if status.success() {
                return Ok(WorktreeHandle {
                    path: target,
                    cleanup: Some(CleanupMode::GitWorktreeRemove {
                        source: source.to_path_buf(),
                    }),
                });
            }
            // Fall through to copy-based worktree.
        }
        Self::from_copy(source, &target)
    }

    /// Copy-based worktree (for repos that aren't git or when `git worktree`
    /// isn't available). Follows symlinks conservatively.
    pub fn from_copy(source: &Path, target: &Path) -> Result<WorktreeHandle> {
        copy_dir(source, target)?;
        Ok(WorktreeHandle {
            path: target.to_path_buf(),
            cleanup: Some(CleanupMode::RemoveDir),
        })
    }
}

fn sanitize(tag: &str) -> String {
    tag.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn is_git(p: &Path) -> bool {
    p.join(".git").exists()
}

fn copy_dir(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        // Skip `.git` and build-output directories that are expensive and
        // rebuildable. Specialists will trigger fresh builds anyway.
        if matches!(
            name.to_str(),
            Some(".git") | Some("target") | Some("node_modules") | Some("build-ods")
        ) {
            continue;
        }
        let to = dst.join(name);
        if path.is_dir() {
            copy_dir(&path, &to)?;
        } else {
            std::fs::copy(&path, &to)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_worktree_mirrors_source() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"hello").unwrap();
        std::fs::create_dir_all(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.txt"), b"world").unwrap();
        std::fs::create_dir_all(src.path().join("target")).unwrap();
        std::fs::write(src.path().join("target/build-artifact"), b"expensive").unwrap();

        let parent = tempfile::tempdir().unwrap();
        let wt = Worktree::from_copy(src.path(), &parent.path().join("copy")).unwrap();
        assert!(wt.path.join("a.txt").exists());
        assert!(wt.path.join("sub/b.txt").exists());
        // target/ should be skipped.
        assert!(!wt.path.join("target").exists());
    }
}
