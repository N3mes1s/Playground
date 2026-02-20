//! # Memory System ("The Brain")
//!
//! The agent's persistent memory with hybrid search:
//! - Full-text search (BM25-scored inverted index)
//! - Vector similarity search (cosine similarity on embeddings)
//! - Hybrid merge with configurable weights
//!
//! In the unikernel, this runs entirely in-kernel memory (no SQLite dependency).
//! The data structures are designed for the heap allocator.

pub mod embeddings;
pub mod chunker;
pub mod hygiene;

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
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
    fn entry_count(&self) -> usize;
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
    /// Cached total token count across all documents (avoids O(n^2) BM25 scoring)
    total_token_count: usize,
    /// Configuration
    vector_weight: f32,
    keyword_weight: f32,
    /// Embedding provider for vector search
    embedding_provider: Option<alloc::boxed::Box<dyn embeddings::EmbeddingProvider>>,
    /// Embedding cache to minimize API calls
    embedding_cache: embeddings::EmbeddingCache,
}

static mut GLOBAL_MEMORY: Option<SpinLock<InKernelMemory>> = None;

/// Initialize the memory system.
pub fn init() {
    let mem = InKernelMemory {
        entries: BTreeMap::new(),
        inverted_index: BTreeMap::new(),
        doc_frequency: BTreeMap::new(),
        total_docs: 0,
        total_token_count: 0,
        vector_weight: 0.6,
        keyword_weight: 0.4,
        embedding_provider: None,
        embedding_cache: embeddings::EmbeddingCache::new(100),
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
    /// Get the number of stored memory entries.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Tokenize text into searchable terms.
    fn tokenize(text: &str) -> Vec<String> {
        crate::util::ascii_lowercase(text)
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| s.len() >= 2)
            .map(String::from)
            .collect()
    }

    /// Add a document to the inverted index.
    fn index_document(&mut self, key: &str, content: &str) {
        let terms = Self::tokenize(content);
        let term_count = terms.len();
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
        self.total_token_count += term_count;
    }

    /// Remove a document from the inverted index.
    fn unindex_document(&mut self, key: &str, content: &str) {
        let terms = Self::tokenize(content);
        let term_count = terms.len();
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
        self.total_token_count = self.total_token_count.saturating_sub(term_count);
    }

    /// BM25 scoring for a query against a document.
    fn bm25_score(&self, query_terms: &[String], doc_content: &str) -> f32 {
        let k1: f32 = 1.2;
        let b: f32 = 0.75;

        let doc_terms = Self::tokenize(doc_content);
        let doc_len = doc_terms.len() as f32;
        // Use cached total_token_count (O(1)) instead of re-tokenizing all entries (O(n*m))
        let avg_doc_len = if self.total_docs > 0 {
            self.total_token_count as f32 / self.total_docs as f32
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
                crate::util::ln_f32((n - df + 0.5) / (df + 0.5) + 1.0)
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

        let denom = crate::util::sqrt_f32(norm_a) * crate::util::sqrt_f32(norm_b);
        if denom == 0.0 { 0.0 } else { dot / denom }
    }

    /// Generate an embedding for text using the configured provider.
    fn generate_embedding(&self, text: &str) -> Option<Vec<f32>> {
        let provider = self.embedding_provider.as_ref()?;

        // Check cache first
        let text_hash = crate::util::fnv1a_hash(text.as_bytes());
        if let Some(cached) = self.embedding_cache.get(text_hash) {
            return Some(cached.clone());
        }

        // Generate via API
        match provider.embed(text) {
            Ok(embedding) => Some(embedding),
            Err(e) => {
                crate::kprintln!("[memory] embedding error: {}", e);
                None
            }
        }
    }

    /// Set the embedding provider for vector search.
    pub fn set_embedding_provider(&mut self, provider: alloc::boxed::Box<dyn embeddings::EmbeddingProvider>) {
        crate::kprintln!("[memory] embedding provider set: {}", provider.name());
        self.embedding_provider = Some(provider);
    }

    /// Run memory hygiene (archival, pruning, deduplication).
    pub fn run_hygiene(&mut self) -> hygiene::HygieneSummary {
        hygiene::run_hygiene(self, &hygiene::HygieneConfig::default())
    }
}

/// Maximum number of memory entries before eviction kicks in.
const MAX_MEMORY_ENTRIES: usize = 30;

impl Memory for InKernelMemory {
    fn store(&mut self, key: &str, content: &str, category: MemoryCategory) -> Result<(), String> {
        // Remove old entry if it exists
        if let Some(old) = self.entries.remove(key) {
            self.unindex_document(key, &old.content);
        }

        // Evict oldest non-core entries if we're at capacity
        while self.entries.len() >= MAX_MEMORY_ENTRIES {
            // Find the oldest non-core entry
            let victim = self.entries.iter()
                .filter(|(_, e)| e.category != MemoryCategory::Core)
                .min_by_key(|(_, e)| e.timestamp)
                .map(|(k, _)| k.clone());

            if let Some(victim_key) = victim {
                if let Some(old) = self.entries.remove(&victim_key) {
                    self.unindex_document(&victim_key, &old.content);
                    crate::kprintln!("[memory] evicted: {}", victim_key);
                }
            } else {
                break; // All entries are core, can't evict
            }
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

        // Generate query embedding if provider is available
        let query_embedding = self.generate_embedding(query);

        let mut results: Vec<SearchResult> = Vec::new();

        for (_, entry) in &self.entries {
            // BM25 keyword score
            let keyword_score = self.bm25_score(&query_terms, &entry.content);

            // Vector similarity score (if embeddings available on both sides)
            let vector_score = match (&query_embedding, &entry.embedding) {
                (Some(q_emb), Some(e_emb)) => Self::cosine_similarity(q_emb, e_emb),
                _ => 0.0f32,
            };

            // Hybrid score: weighted combination
            let score = if vector_score > 0.0 {
                // Both scores available — use weighted hybrid
                self.keyword_weight * keyword_score + self.vector_weight * vector_score
            } else {
                // Keyword-only fallback (full weight to keywords)
                keyword_score
            };

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

    fn entry_count(&self) -> usize {
        self.entries.len()
    }
}
