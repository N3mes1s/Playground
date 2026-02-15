//! # Markdown Semantic Chunker
//!
//! Splits large text content into semantically meaningful chunks
//! for better search relevance. Preserves heading hierarchy so
//! each chunk has context about where it came from.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// A chunk of text with its heading context.
#[derive(Debug, Clone)]
pub struct Chunk {
    /// The heading path (e.g., "# Title > ## Section > ### Subsection")
    pub heading_path: String,
    /// The chunk content
    pub content: String,
    /// Approximate character position in the original document
    pub offset: usize,
}

/// Configuration for the chunker.
#[derive(Debug, Clone)]
pub struct ChunkerConfig {
    /// Target chunk size in characters
    pub target_size: usize,
    /// Maximum chunk size (hard limit)
    pub max_size: usize,
    /// Minimum chunk size (don't create tiny chunks)
    pub min_size: usize,
    /// Overlap between consecutive chunks (for context continuity)
    pub overlap: usize,
}

impl Default for ChunkerConfig {
    fn default() -> Self {
        ChunkerConfig {
            target_size: 512,
            max_size: 1024,
            min_size: 64,
            overlap: 50,
        }
    }
}

/// Split markdown content into semantically meaningful chunks.
pub fn chunk_markdown(content: &str, config: &ChunkerConfig) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut heading_stack: Vec<(usize, String)> = Vec::new(); // (level, text)
    let mut current_content = String::new();
    let mut current_offset = 0usize;

    for (line_offset, line) in content.lines().enumerate() {
        let trimmed = line.trim();

        // Check if this is a heading
        if let Some(heading) = parse_heading(trimmed) {
            // Flush current content as a chunk
            if current_content.len() >= config.min_size {
                chunks.push(Chunk {
                    heading_path: build_heading_path(&heading_stack),
                    content: current_content.clone(),
                    offset: current_offset,
                });
                current_content.clear();
            }

            // Update heading stack
            let level = heading.0;
            // Pop headings of equal or greater level
            while heading_stack.last().map_or(false, |(l, _)| *l >= level) {
                heading_stack.pop();
            }
            heading_stack.push(heading);
            current_offset = line_offset;
        } else {
            // Accumulate content
            if !current_content.is_empty() {
                current_content.push('\n');
            }
            current_content.push_str(line);

            // Check if we've exceeded max size
            if current_content.len() >= config.max_size {
                // Split at the last sentence or paragraph boundary
                let split_point = find_split_point(&current_content, config.target_size);
                let (chunk_text, remainder) = current_content.split_at(split_point);

                chunks.push(Chunk {
                    heading_path: build_heading_path(&heading_stack),
                    content: String::from(chunk_text.trim()),
                    offset: current_offset,
                });

                // Keep overlap for context continuity
                let overlap_start = if remainder.len() > config.overlap {
                    remainder.len() - config.overlap
                } else {
                    0
                };
                current_content = String::from(&remainder[overlap_start..]);
                current_offset = line_offset;
            }
        }
    }

    // Flush remaining content
    if current_content.len() >= config.min_size {
        chunks.push(Chunk {
            heading_path: build_heading_path(&heading_stack),
            content: current_content,
            offset: current_offset,
        });
    } else if !current_content.is_empty() {
        // Append to last chunk if too small
        if let Some(last) = chunks.last_mut() {
            last.content.push('\n');
            last.content.push_str(&current_content);
        } else {
            chunks.push(Chunk {
                heading_path: build_heading_path(&heading_stack),
                content: current_content,
                offset: current_offset,
            });
        }
    }

    chunks
}

/// Parse a markdown heading line. Returns (level, text).
fn parse_heading(line: &str) -> Option<(usize, String)> {
    let mut level = 0;
    for c in line.chars() {
        if c == '#' {
            level += 1;
        } else {
            break;
        }
    }
    if level > 0 && level <= 6 {
        let text = line[level..].trim().to_string();
        if !text.is_empty() {
            return Some((level, text));
        }
    }
    None
}

/// Build a heading path string from the heading stack.
fn build_heading_path(stack: &[(usize, String)]) -> String {
    if stack.is_empty() {
        return String::from("(document root)");
    }
    stack.iter()
        .map(|(_, text)| text.as_str())
        .collect::<Vec<_>>()
        .join(" > ")
}

/// Find the best split point near the target size.
/// Prefers paragraph boundaries > sentence boundaries > word boundaries.
fn find_split_point(text: &str, target: usize) -> usize {
    let target = core::cmp::min(target, text.len());

    // Try to split at a paragraph boundary (double newline)
    if let Some(pos) = text[..target].rfind("\n\n") {
        return pos + 2;
    }

    // Try to split at a sentence boundary
    for &delim in &[". ", "! ", "? ", ".\n", "!\n", "?\n"] {
        if let Some(pos) = text[..target].rfind(delim) {
            return pos + delim.len();
        }
    }

    // Try to split at a newline
    if let Some(pos) = text[..target].rfind('\n') {
        return pos + 1;
    }

    // Last resort: split at a word boundary
    if let Some(pos) = text[..target].rfind(' ') {
        return pos + 1;
    }

    // Absolute last resort: split at target
    target
}

/// Chunk plain text (non-markdown) into fixed-size chunks with overlap.
pub fn chunk_plain(content: &str, config: &ChunkerConfig) -> Vec<Chunk> {
    let mut chunks = Vec::new();
    let mut start = 0;

    while start < content.len() {
        let end = core::cmp::min(start + config.target_size, content.len());
        let split = if end < content.len() {
            find_split_point(&content[start..end], config.target_size) + start
        } else {
            end
        };

        let chunk_text = &content[start..split];
        if chunk_text.len() >= config.min_size || chunks.is_empty() {
            chunks.push(Chunk {
                heading_path: String::new(),
                content: String::from(chunk_text.trim()),
                offset: start,
            });
        }

        // Advance with overlap
        start = if split > config.overlap {
            split - config.overlap
        } else {
            split
        };

        // Prevent infinite loop
        if start >= split {
            start = split;
        }
    }

    chunks
}
