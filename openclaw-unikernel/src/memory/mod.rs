//! # Memory System ("The Brain")
//!
//! The agent's persistent memory with hybrid search:
//! - Full-text search (BM25-scored inverted index)
//! - Vector similarity search (cosine similarity on embeddings)
//! - Hybrid merge with configurable weights
//!
//! In the unikernel, this runs entirely in-kernel memory (no SQLite dependency).
//! The data structures are designed for the heap allocator.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use crate::kernel::sync::SpinLock;

/// Memory categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemoryCategory {
    Core,
    Daily,
    Conversation,
    Archive,
}

impl MemoryCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryCategory::Core => "core",
            MemoryCategory::Daily => "daily",
            MemoryCategory::Conversation => "conversation",
            MemoryCategory::Archive => "archive",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s {
            "core" => MemoryCategory::Core,
            "daily" => MemoryCategory::Daily,
            "conversation" => MemoryCategory::Conversation,
            "archive" => MemoryCategory::Archive,
            _ => MemoryCategory::Daily,
        }
    }
}

/// A single memory entry.
#[derive(Debug, Clone)]
pub struct MemoryEntry {
    pub key: String,
    pub content: String,
    pub category: MemoryCategory,
    pub timestamp: u64,
    pub embedding: Option<Vec<f32>>,
    pub access_count: u32,
}

/// Search result with relevance score.
#[derive(Debug, Clone)]
pub struct SearchResult {
    pub entry: MemoryEntry,
    pub score: f32,
}

/// Memory trait — backend abstraction.
pub trait Memory: Send {
    fn store(&mut self, key: &str, content: &str, category: MemoryCategory) -> Result<(), String>;
    fn recall(&self, query: &str, limit: usize) -> Vec<SearchResult>;
    fn forget(&mut self, key: &str) -> bool;
    fn list(&self, category: Option<MemoryCategory>) -> Vec<MemoryEntry>;
    fn count(&self) -> usize;
}

// ── In-Kernel Memory Store ─────────────────────────────────────────────────

/// The main in-kernel memory store with full-text + vector search.
pub struct InKernelMemory {
    /// All memory entries, keyed by unique key
    entries: BTreeMap<String, MemoryEntry>,
    /// Inverted index: term → set of entry keys (for FTS)
    inverted_index: BTreeMap<String, Vec<String>>,
    /// Document frequency: term → number of documents containing it
    doc_frequency: BTreeMap<String, u32>,
    /// Total documents indexed
    total_docs: u32,
    /// Configuration
    vector_weight: f32,
    keyword_weight: f32,
}

static mut GLOBAL_MEMORY: Option<SpinLock<InKernelMemory>> = None;

/// Initialize the memory system.
pub fn init() {
    let mem = InKernelMemory {
        entries: BTreeMap::new(),
        inverted_index: BTreeMap::new(),
        doc_frequency: BTreeMap::new(),
        total_docs: 0,
        vector_weight: 0.6,
        keyword_weight: 0.4,
    };
    unsafe {
        GLOBAL_MEMORY = Some(SpinLock::new(mem));
    }
}

/// Get a reference to the global memory (locked).
pub fn global() -> &'static SpinLock<InKernelMemory> {
    unsafe { GLOBAL_MEMORY.as_ref().expect("memory not initialized") }
}

impl InKernelMemory {
    /// Tokenize text into searchable terms.
    fn tokenize(text: &str) -> Vec<String> {
        text.to_ascii_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| s.len() >= 2)
            .map(String::from)
            .collect()
    }

    /// Add a document to the inverted index.
    fn index_document(&mut self, key: &str, content: &str) {
        let terms = Self::tokenize(content);
        let mut seen = alloc::collections::BTreeSet::new();

        for term in &terms {
            // Add to inverted index
            self.inverted_index
                .entry(term.clone())
                .or_insert_with(Vec::new)
                .push(String::from(key));

            // Track document frequency (once per unique term per doc)
            if seen.insert(term.clone()) {
                *self.doc_frequency.entry(term.clone()).or_insert(0) += 1;
            }
        }

        self.total_docs += 1;
    }

    /// Remove a document from the inverted index.
    fn unindex_document(&mut self, key: &str, content: &str) {
        let terms = Self::tokenize(content);
        let mut seen = alloc::collections::BTreeSet::new();

        for term in &terms {
            if let Some(keys) = self.inverted_index.get_mut(term) {
                keys.retain(|k| k != key);
                if keys.is_empty() {
                    self.inverted_index.remove(term);
                }
            }

            if seen.insert(term.clone()) {
                if let Some(df) = self.doc_frequency.get_mut(term) {
                    *df = df.saturating_sub(1);
                    if *df == 0 {
                        self.doc_frequency.remove(term);
                    }
                }
            }
        }

        self.total_docs = self.total_docs.saturating_sub(1);
    }

    /// BM25 scoring for a query against a document.
    fn bm25_score(&self, query_terms: &[String], doc_content: &str) -> f32 {
        let k1: f32 = 1.2;
        let b: f32 = 0.75;

        let doc_terms = Self::tokenize(doc_content);
        let doc_len = doc_terms.len() as f32;
        let avg_doc_len = if self.total_docs > 0 {
            // Approximate average document length
            let total_terms: usize = self.entries.values()
                .map(|e| Self::tokenize(&e.content).len())
                .sum();
            total_terms as f32 / self.total_docs as f32
        } else {
            1.0
        };

        let mut score: f32 = 0.0;
        for term in query_terms {
            // Term frequency in document
            let tf = doc_terms.iter().filter(|t| *t == term).count() as f32;
            // Document frequency
            let df = self.doc_frequency.get(term).copied().unwrap_or(0) as f32;
            // Inverse document frequency
            let n = self.total_docs as f32;
            let idf = if df > 0.0 {
                ((n - df + 0.5) / (df + 0.5) + 1.0).ln()
            } else {
                0.0
            };

            let tf_norm = (tf * (k1 + 1.0)) / (tf + k1 * (1.0 - b + b * doc_len / avg_doc_len));
            score += idf * tf_norm;
        }

        score
    }

    /// Cosine similarity between two vectors.
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }

        let mut dot: f32 = 0.0;
        let mut norm_a: f32 = 0.0;
        let mut norm_b: f32 = 0.0;

        for i in 0..a.len() {
            dot += a[i] * b[i];
            norm_a += a[i] * a[i];
            norm_b += b[i] * b[i];
        }

        let denom = norm_a.sqrt() * norm_b.sqrt();
        if denom == 0.0 { 0.0 } else { dot / denom }
    }
}

impl Memory for InKernelMemory {
    fn store(&mut self, key: &str, content: &str, category: MemoryCategory) -> Result<(), String> {
        // Remove old entry if it exists
        if let Some(old) = self.entries.remove(key) {
            self.unindex_document(key, &old.content);
        }

        let entry = MemoryEntry {
            key: String::from(key),
            content: String::from(content),
            category,
            timestamp: crate::kernel::rdtsc(),
            embedding: None, // Embeddings are set separately
            access_count: 0,
        };

        self.index_document(key, content);
        self.entries.insert(String::from(key), entry);
        Ok(())
    }

    fn recall(&self, query: &str, limit: usize) -> Vec<SearchResult> {
        let query_terms = Self::tokenize(query);
        let mut results: Vec<SearchResult> = Vec::new();

        for (_, entry) in &self.entries {
            // BM25 keyword score
            let keyword_score = self.bm25_score(&query_terms, &entry.content);

            // Vector similarity score (if embeddings available)
            let vector_score = 0.0f32; // Would use embeddings when available

            // Hybrid score
            let score = self.keyword_weight * keyword_score + self.vector_weight * vector_score;

            if score > 0.0 {
                results.push(SearchResult {
                    entry: entry.clone(),
                    score,
                });
            }
        }

        // Sort by score descending
        results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(core::cmp::Ordering::Equal));
        results.truncate(limit);
        results
    }

    fn forget(&mut self, key: &str) -> bool {
        if let Some(entry) = self.entries.remove(key) {
            self.unindex_document(key, &entry.content);
            true
        } else {
            false
        }
    }

    fn list(&self, category: Option<MemoryCategory>) -> Vec<MemoryEntry> {
        self.entries
            .values()
            .filter(|e| category.map_or(true, |c| e.category == c))
            .cloned()
            .collect()
    }

    fn count(&self) -> usize {
        self.entries.len()
    }
}
