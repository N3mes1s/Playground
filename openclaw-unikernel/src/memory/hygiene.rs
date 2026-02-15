//! # Memory Hygiene
//!
//! Automated memory lifecycle management:
//! - Archives old daily entries
//! - Prunes conversation entries past retention period
//! - Deduplicates similar entries
//! - Enforces memory limits

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use super::{MemoryCategory, MemoryEntry, Memory, InKernelMemory};
use core::sync::atomic::{AtomicU64, Ordering};

static LAST_HYGIENE_RUN: AtomicU64 = AtomicU64::new(0);

/// Hygiene configuration.
#[derive(Debug, Clone)]
pub struct HygieneConfig {
    /// Maximum number of daily entries before archiving
    pub max_daily_entries: usize,
    /// Maximum number of conversation entries before pruning
    pub max_conversation_entries: usize,
    /// Maximum total memory entries
    pub max_total_entries: usize,
    /// TSC ticks between hygiene runs (~12 hours at 2GHz)
    pub run_interval_ticks: u64,
    /// Similarity threshold for deduplication (0.0 - 1.0)
    pub dedup_threshold: f32,
}

impl Default for HygieneConfig {
    fn default() -> Self {
        HygieneConfig {
            max_daily_entries: 500,
            max_conversation_entries: 200,
            max_total_entries: 5000,
            run_interval_ticks: 86_400_000_000_000, // ~12 hours at 2GHz
            dedup_threshold: 0.95,
        }
    }
}

/// Run a hygiene cycle on the memory store.
/// Returns a summary of actions taken.
pub fn run_hygiene(memory: &mut InKernelMemory, config: &HygieneConfig) -> HygieneSummary {
    let now = crate::kernel::rdtsc();
    let last = LAST_HYGIENE_RUN.load(Ordering::Relaxed);

    if now - last < config.run_interval_ticks && last > 0 {
        return HygieneSummary::default();
    }

    LAST_HYGIENE_RUN.store(now, Ordering::Relaxed);

    let mut summary = HygieneSummary::default();

    // Phase 1: Archive old daily entries
    summary.archived += archive_daily(memory, config.max_daily_entries);

    // Phase 2: Prune old conversation entries
    summary.pruned += prune_conversations(memory, config.max_conversation_entries);

    // Phase 3: Deduplicate similar entries
    summary.deduplicated += deduplicate(memory, config.dedup_threshold);

    // Phase 4: Enforce total memory limit
    summary.evicted += enforce_limit(memory, config.max_total_entries);

    if summary.total_actions() > 0 {
        crate::kprintln!(
            "[hygiene] archived={}, pruned={}, deduped={}, evicted={}",
            summary.archived, summary.pruned, summary.deduplicated, summary.evicted
        );
    }

    summary
}

/// Archive old daily entries by moving them to the archive category.
fn archive_daily(memory: &mut InKernelMemory, max_entries: usize) -> usize {
    let daily_entries: Vec<MemoryEntry> = memory
        .list(Some(MemoryCategory::Daily))
        .into_iter()
        .collect();

    if daily_entries.len() <= max_entries {
        return 0;
    }

    let mut sorted = daily_entries;
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let to_archive = sorted.len() - max_entries;
    let mut archived = 0;

    for entry in sorted.iter().take(to_archive) {
        // Move to archive category
        memory.forget(&entry.key);
        let archive_key = format!("archive-{}", entry.key);
        let _ = memory.store(&archive_key, &entry.content, MemoryCategory::Archive);
        archived += 1;
    }

    archived
}

/// Prune old conversation entries.
fn prune_conversations(memory: &mut InKernelMemory, max_entries: usize) -> usize {
    let conv_entries: Vec<MemoryEntry> = memory
        .list(Some(MemoryCategory::Conversation))
        .into_iter()
        .collect();

    if conv_entries.len() <= max_entries {
        return 0;
    }

    let mut sorted = conv_entries;
    sorted.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let to_prune = sorted.len() - max_entries;
    let mut pruned = 0;

    for entry in sorted.iter().take(to_prune) {
        memory.forget(&entry.key);
        pruned += 1;
    }

    pruned
}

/// Deduplicate entries with very similar content.
fn deduplicate(memory: &mut InKernelMemory, threshold: f32) -> usize {
    let all_entries: Vec<MemoryEntry> = memory.list(None);
    let mut to_remove: Vec<String> = Vec::new();

    // Compare each pair (O(n^2) but memory stores are typically small)
    for i in 0..all_entries.len() {
        if to_remove.contains(&all_entries[i].key) {
            continue;
        }
        for j in (i + 1)..all_entries.len() {
            if to_remove.contains(&all_entries[j].key) {
                continue;
            }

            let similarity = jaccard_similarity(
                &all_entries[i].content,
                &all_entries[j].content,
            );

            if similarity >= threshold {
                // Keep the newer entry, remove the older one
                if all_entries[i].timestamp < all_entries[j].timestamp {
                    to_remove.push(all_entries[i].key.clone());
                } else {
                    to_remove.push(all_entries[j].key.clone());
                }
            }
        }
    }

    let count = to_remove.len();
    for key in &to_remove {
        memory.forget(key);
    }

    count
}

/// Enforce maximum total entry count by evicting oldest low-access entries.
fn enforce_limit(memory: &mut InKernelMemory, max_entries: usize) -> usize {
    let total = memory.count();
    if total <= max_entries {
        return 0;
    }

    let excess = total - max_entries;

    // Get all non-core entries sorted by timestamp (oldest first)
    let mut candidates: Vec<MemoryEntry> = memory
        .list(None)
        .into_iter()
        .filter(|e| e.category != MemoryCategory::Core)
        .collect();

    candidates.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let mut evicted = 0;
    for entry in candidates.iter().take(excess) {
        memory.forget(&entry.key);
        evicted += 1;
    }

    evicted
}

/// Jaccard similarity between two texts (based on word sets).
fn jaccard_similarity(a: &str, b: &str) -> f32 {
    let words_a: alloc::collections::BTreeSet<&str> = a.split_whitespace().collect();
    let words_b: alloc::collections::BTreeSet<&str> = b.split_whitespace().collect();

    if words_a.is_empty() && words_b.is_empty() {
        return 1.0;
    }

    let intersection = words_a.intersection(&words_b).count();
    let union = words_a.union(&words_b).count();

    if union == 0 { 0.0 } else { intersection as f32 / union as f32 }
}

/// Summary of hygiene actions taken.
#[derive(Debug, Clone, Default)]
pub struct HygieneSummary {
    pub archived: usize,
    pub pruned: usize,
    pub deduplicated: usize,
    pub evicted: usize,
}

impl HygieneSummary {
    pub fn total_actions(&self) -> usize {
        self.archived + self.pruned + self.deduplicated + self.evicted
    }
}
