//! SFP (SQL Server Forge Pack) archive parser
//!
//! SFP is Microsoft's proprietary archive format used by SQL Server on Linux
//! to package the Library OS (system.sfp) and SQL Server binaries (sqlservr.sfp).
//!
//! File format (reverse-engineered from nta/sfpack):
//! ```text
//! +------------------+
//! | SFP Header       |  Magic, version, offsets to directory/names/data
//! +------------------+
//! | Directory Table  |  Array of entries (name offset, flags, size, data offset)
//! +------------------+
//! | Name Table       |  UTF-16LE strings for file/directory names
//! +------------------+
//! | Data Section     |  Raw file contents
//! +------------------+
//! ```

use anyhow::{bail, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use std::collections::HashMap;
use std::io::{Cursor, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// SFP archive magic number
const SFP_MAGIC: u64 = 0x0050_4653; // "SFP\0" in little-endian

/// SFP file header
#[derive(Debug, Clone)]
pub struct SfpHeader {
    pub magic: u64,
    pub version: u64,
    pub first_dir_offset: u64,
    pub name_table_offset: u64,
    pub data_offset: u64,
    pub archive_size: u64,
}

impl SfpHeader {
    pub fn parse(data: &[u8]) -> Result<Self> {
        if data.len() < 48 {
            bail!("SFP header too short ({} bytes, need 48)", data.len());
        }
        let mut cursor = Cursor::new(data);
        Ok(SfpHeader {
            magic: cursor.read_u64::<LittleEndian>()?,
            version: cursor.read_u64::<LittleEndian>()?,
            first_dir_offset: cursor.read_u64::<LittleEndian>()?,
            name_table_offset: cursor.read_u64::<LittleEndian>()?,
            data_offset: cursor.read_u64::<LittleEndian>()?,
            archive_size: cursor.read_u64::<LittleEndian>()?,
        })
    }

    pub fn is_valid(&self) -> bool {
        // The magic might vary - we accept a range
        self.first_dir_offset > 0
            && self.name_table_offset > 0
            && self.data_offset > 0
            && self.archive_size > 0
    }
}

/// A directory entry in the SFP archive
#[derive(Debug, Clone)]
pub struct SfpDirEntry {
    pub name_offset: u64,
    pub is_directory: bool,
    pub file_length: u64,
    pub timestamp_created: u64,
    pub timestamp_modified: u64,
    pub data_start_offset: u64,
    pub data_length: u64,
    /// Resolved name (from name table)
    pub name: String,
    /// Full path within archive
    pub full_path: PathBuf,
}

/// Parsed SFP archive
#[derive(Debug)]
pub struct SfpArchive {
    pub header: SfpHeader,
    pub entries: Vec<SfpDirEntry>,
    pub files: HashMap<PathBuf, SfpDirEntry>,
    raw_data: Vec<u8>,
}

impl SfpArchive {
    /// Parse an SFP archive from raw bytes
    pub fn parse(data: Vec<u8>) -> Result<Self> {
        let header = SfpHeader::parse(&data)?;

        // Try to parse directory entries
        let mut entries = Vec::new();
        let mut cursor = Cursor::new(&data);

        // Seek to directory table
        cursor.seek(SeekFrom::Start(header.first_dir_offset))?;

        // Parse directory entries until we hit the name table
        let dir_area_end = header.name_table_offset.min(data.len() as u64);

        while cursor.position() + 48 <= dir_area_end {
            let entry_start = cursor.position();

            // Read entry fields (approximate format from sfpack source)
            let name_offset = cursor.read_u64::<LittleEndian>()?;
            let flags = cursor.read_u64::<LittleEndian>()?;
            let file_length = cursor.read_u64::<LittleEndian>()?;
            let ts_created = cursor.read_u64::<LittleEndian>()?;
            let ts_modified = cursor.read_u64::<LittleEndian>()?;
            let data_start = cursor.read_u64::<LittleEndian>()?;
            let data_length = cursor.read_u64::<LittleEndian>()?;

            // Sanity check - if fields look invalid, stop
            if name_offset > data.len() as u64 || data_start > data.len() as u64 {
                break;
            }

            let is_dir = (flags & 1) != 0;

            // Resolve name from name table
            let name = resolve_name(&data, header.name_table_offset, name_offset);

            if name.is_empty() && entries.len() > 2 {
                // Probably hit end of directory
                break;
            }

            entries.push(SfpDirEntry {
                name_offset,
                is_directory: is_dir,
                file_length,
                timestamp_created: ts_created,
                timestamp_modified: ts_modified,
                data_start_offset: data_start,
                data_length,
                name: name.clone(),
                full_path: PathBuf::from(&name),
            });

            // Skip any remaining entry data (entries might be larger than 56 bytes)
            let consumed = cursor.position() - entry_start;
            if consumed < 64 {
                cursor.seek(SeekFrom::Current(64 - consumed as i64))?;
            }
        }

        // Build file index
        let mut files = HashMap::new();
        for entry in &entries {
            if !entry.is_directory {
                files.insert(entry.full_path.clone(), entry.clone());
            }
        }

        Ok(SfpArchive {
            header,
            entries,
            files,
            raw_data: data,
        })
    }

    /// Extract a file's contents from the archive
    pub fn extract_file(&self, entry: &SfpDirEntry) -> Result<Vec<u8>> {
        let start = entry.data_start_offset as usize;
        let end = start + entry.data_length as usize;

        if end > self.raw_data.len() {
            bail!(
                "File data exceeds archive bounds: {}..{} > {}",
                start,
                end,
                self.raw_data.len()
            );
        }

        Ok(self.raw_data[start..end].to_vec())
    }

    /// Extract all files to a directory
    pub fn extract_all(&self, output_dir: &Path) -> Result<Vec<PathBuf>> {
        let mut extracted = Vec::new();

        for entry in &self.entries {
            let output_path = output_dir.join(&entry.full_path);

            if entry.is_directory {
                std::fs::create_dir_all(&output_path)
                    .with_context(|| format!("Failed to create dir: {}", output_path.display()))?;
            } else {
                if let Some(parent) = output_path.parent() {
                    std::fs::create_dir_all(parent)?;
                }

                let data = self.extract_file(entry)?;
                std::fs::write(&output_path, &data)
                    .with_context(|| format!("Failed to write: {}", output_path.display()))?;

                extracted.push(output_path);
            }
        }

        Ok(extracted)
    }

    /// List all files with their sizes
    pub fn list_files(&self) -> Vec<(String, u64, bool)> {
        self.entries
            .iter()
            .map(|e| (e.name.clone(), e.file_length, e.is_directory))
            .collect()
    }

    /// Find entries by extension
    pub fn find_by_extension(&self, ext: &str) -> Vec<&SfpDirEntry> {
        self.entries
            .iter()
            .filter(|e| {
                !e.is_directory
                    && e.name
                        .to_lowercase()
                        .ends_with(&format!(".{}", ext.to_lowercase()))
            })
            .collect()
    }

    /// Find NTUM-critical files
    pub fn find_ntum_components(&self) -> Vec<&SfpDirEntry> {
        let critical_names = [
            "ntoskrnl", "ntdll", "win32k", "kerberos", "windows.hiv",
            ".dbpatch", ".dbmanifest", ".bin.ini", "sqlservr.exe",
        ];

        self.entries
            .iter()
            .filter(|e| {
                let name_lower = e.name.to_lowercase();
                critical_names
                    .iter()
                    .any(|c| name_lower.contains(&c.to_lowercase()))
            })
            .collect()
    }
}

/// Resolve a name from the SFP name table (UTF-16LE strings)
fn resolve_name(data: &[u8], name_table_base: u64, name_offset: u64) -> String {
    let abs_offset = (name_table_base + name_offset) as usize;
    if abs_offset >= data.len() {
        return String::new();
    }

    // Try UTF-16LE first (common in SFP)
    let remaining = &data[abs_offset..];
    let mut utf16_chars = Vec::new();

    let mut i = 0;
    while i + 1 < remaining.len() {
        let ch = u16::from_le_bytes([remaining[i], remaining[i + 1]]);
        if ch == 0 {
            break;
        }
        utf16_chars.push(ch);
        i += 2;
    }

    if !utf16_chars.is_empty() {
        if let Ok(s) = String::from_utf16(&utf16_chars) {
            if s.chars().all(|c| c.is_ascii_graphic() || c == ' ' || c == '.' || c == '\\' || c == '/') {
                return s;
            }
        }
    }

    // Fallback: try ASCII/UTF-8
    let end = remaining.iter().position(|&b| b == 0).unwrap_or(remaining.len().min(256));
    String::from_utf8_lossy(&remaining[..end]).to_string()
}

/// Detect if a file is an SFP archive by checking the header
pub fn is_sfp_file(path: &Path) -> bool {
    if let Ok(data) = std::fs::read(path) {
        if data.len() >= 48 {
            if let Ok(header) = SfpHeader::parse(&data) {
                return header.is_valid();
            }
        }
    }
    false
}
