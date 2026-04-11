//! NTUM (NT User-Mode kernel) loader
//!
//! This module handles loading and initializing the extracted NTUM from
//! SQL Server on Linux's system.sfp. The NTUM is the core of Drawbridge's
//! Library OS - a real Windows kernel running in user mode.
//!
//! Loading sequence (matching what SQLPAL's palrun does):
//! 1. Read ntoskrnl.dll.bin.ini for memory layout
//! 2. Map ntoskrnl.dll.bin into memory at specified addresses
//! 3. Apply .dbpatch files to redirect syscalls to PAL
//! 4. Load target PE executable using the Library OS PE loader
//! 5. Transfer control to the PE entry point

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::dbpatch;
use crate::pal;
use crate::pe;

/// Memory layout specification from a .bin.ini file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinIniLayout {
    /// Base virtual address where the binary should be loaded
    pub base_address: u64,
    /// Total size to map
    pub total_size: u64,
    /// Sections with their offsets, sizes, and permissions
    pub sections: Vec<BinIniSection>,
    /// Raw key-value pairs from the INI file
    pub raw_config: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinIniSection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub virtual_address: u64,
    pub protection: String, // "rwx", "r-x", "rw-", etc.
}

/// The loaded NTUM state
#[derive(Debug)]
pub struct NtumState {
    /// Path to the extracted NTUM directory
    pub ntum_dir: PathBuf,
    /// Memory layout from .bin.ini
    pub layout: Option<BinIniLayout>,
    /// Base address where ntoskrnl.dll.bin is mapped
    pub kernel_base: *mut u8,
    /// Size of mapped kernel
    pub kernel_size: usize,
    /// dbpatch entries that were applied
    pub applied_patches: Vec<dbpatch::PatchEntry>,
    /// PE analysis of loaded DLLs
    pub loaded_dlls: Vec<pe::PeAnalysis>,
    /// PAL report
    pub pal_info: pal::PalReport,
}

impl NtumState {
    pub fn new(ntum_dir: &Path) -> Self {
        NtumState {
            ntum_dir: ntum_dir.to_path_buf(),
            layout: None,
            kernel_base: std::ptr::null_mut(),
            kernel_size: 0,
            applied_patches: Vec::new(),
            loaded_dlls: Vec::new(),
            pal_info: pal::pal_report(),
        }
    }
}

/// Parse a .bin.ini file that describes the memory layout for a raw binary image
///
/// Format (reverse-engineered):
/// ```ini
/// [Main]
/// BaseAddress=0x7FF600000000
/// TotalSize=0x1000000
///
/// [Section.text]
/// Offset=0x1000
/// Size=0x800000
/// VirtualAddress=0x1000
/// Protection=r-x
/// ```
pub fn parse_bin_ini(path: &Path) -> Result<BinIniLayout> {
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read: {}", path.display()))?;

    let mut raw_config = HashMap::new();
    let mut sections = Vec::new();
    let mut base_address = 0u64;
    let mut total_size = 0u64;
    let mut current_section: Option<String> = None;
    let mut section_data: HashMap<String, String> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }

        if line.starts_with('[') && line.ends_with(']') {
            // Save previous section
            if let Some(ref name) = current_section {
                if name.starts_with("Section") || name.starts_with("section") {
                    sections.push(parse_section_data(name, &section_data));
                }
            }
            current_section = Some(line[1..line.len() - 1].to_string());
            section_data.clear();
            continue;
        }

        if let Some(eq_pos) = line.find('=') {
            let key = line[..eq_pos].trim().to_string();
            let value = line[eq_pos + 1..].trim().to_string();

            raw_config.insert(
                format!(
                    "{}.{}",
                    current_section.as_deref().unwrap_or("global"),
                    &key
                ),
                value.clone(),
            );

            match key.to_lowercase().as_str() {
                "baseaddress" | "base_address" | "imagebase" => {
                    base_address = parse_hex_or_dec(&value);
                }
                "totalsize" | "total_size" | "sizeofimage" => {
                    total_size = parse_hex_or_dec(&value);
                }
                _ => {}
            }

            section_data.insert(key, value);
        }
    }

    // Save last section
    if let Some(ref name) = current_section {
        if name.starts_with("Section") || name.starts_with("section") {
            sections.push(parse_section_data(name, &section_data));
        }
    }

    Ok(BinIniLayout {
        base_address,
        total_size,
        sections,
        raw_config,
    })
}

fn parse_section_data(name: &str, data: &HashMap<String, String>) -> BinIniSection {
    BinIniSection {
        name: name.to_string(),
        offset: data
            .get("Offset")
            .or_else(|| data.get("offset"))
            .map(|v| parse_hex_or_dec(v))
            .unwrap_or(0),
        size: data
            .get("Size")
            .or_else(|| data.get("size"))
            .map(|v| parse_hex_or_dec(v))
            .unwrap_or(0),
        virtual_address: data
            .get("VirtualAddress")
            .or_else(|| data.get("virtual_address"))
            .or_else(|| data.get("VA"))
            .map(|v| parse_hex_or_dec(v))
            .unwrap_or(0),
        protection: data
            .get("Protection")
            .or_else(|| data.get("protection"))
            .or_else(|| data.get("Protect"))
            .cloned()
            .unwrap_or_else(|| "r--".to_string()),
    }
}

fn parse_hex_or_dec(s: &str) -> u64 {
    let s = s.trim();
    if s.starts_with("0x") || s.starts_with("0X") {
        u64::from_str_radix(&s[2..], 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

/// Protection string to PAL protection
fn prot_string_to_pal(s: &str) -> pal::PalProt {
    let s = s.to_lowercase();
    let r = s.contains('r');
    let w = s.contains('w');
    let x = s.contains('x');

    match (r, w, x) {
        (true, true, true) => pal::PalProt::READ_WRITE_EXEC,
        (true, true, false) => pal::PalProt::READ_WRITE,
        (true, false, true) => pal::PalProt::READ_EXEC,
        (true, false, false) => pal::PalProt::READ,
        (false, true, false) => pal::PalProt::WRITE,
        (false, false, true) => pal::PalProt::EXEC,
        _ => pal::PalProt::NONE,
    }
}

/// Load the NTUM kernel image into memory
///
/// This is the core of what SQLPAL's palrun does:
/// 1. Read .bin.ini for memory layout
/// 2. Allocate memory via PAL at specified base address
/// 3. Copy raw binary image into mapped memory
/// 4. Set section permissions
pub fn load_ntum_kernel(
    bin_path: &Path,
    ini_path: Option<&Path>,
) -> Result<(*mut u8, usize, Option<BinIniLayout>)> {
    let kernel_data =
        std::fs::read(bin_path).with_context(|| format!("Failed to read: {}", bin_path.display()))?;

    let layout = if let Some(ini) = ini_path {
        Some(parse_bin_ini(ini)?)
    } else {
        None
    };

    // Determine where to load
    let base_addr = layout.as_ref().map(|l| l.base_address).unwrap_or(0);
    let total_size = layout
        .as_ref()
        .map(|l| {
            if l.total_size > 0 {
                l.total_size as usize
            } else {
                kernel_data.len()
            }
        })
        .unwrap_or(kernel_data.len());

    // Round up to page size
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize };
    let alloc_size = (total_size + page_size - 1) & !(page_size - 1);

    // Allocate via PAL
    let addr_hint = if base_addr != 0 {
        Some(base_addr as *mut u8)
    } else {
        None
    };

    let mapped = pal::pal_virtual_memory_alloc(addr_hint, alloc_size, pal::PalProt::READ_WRITE)?;

    // Copy kernel image
    let copy_size = kernel_data.len().min(alloc_size);
    unsafe {
        std::ptr::copy_nonoverlapping(kernel_data.as_ptr(), mapped, copy_size);
    }

    // Apply section permissions if we have layout info
    if let Some(ref layout) = layout {
        for section in &layout.sections {
            if section.size == 0 {
                continue;
            }

            let section_addr = unsafe { mapped.add(section.virtual_address as usize) };
            let section_size = (section.size as usize + page_size - 1) & !(page_size - 1);
            let prot = prot_string_to_pal(&section.protection);

            if let Err(e) = pal::pal_virtual_memory_protect(section_addr, section_size, prot) {
                eprintln!(
                    "Warning: Failed to set protection for section {}: {}",
                    section.name, e
                );
            }
        }
    }

    Ok((mapped, alloc_size, layout))
}

/// Apply .dbpatch patches to a mapped DLL
///
/// This replicates what SQLPAL does: take a real Windows DLL loaded in memory
/// and replace syscall instructions with PAL downcall stubs.
pub fn apply_dbpatch(
    dll_base: *mut u8,
    dll_size: usize,
    patches: &dbpatch::DbPatchFile,
) -> Result<Vec<dbpatch::PatchEntry>> {
    let mut applied = Vec::new();

    // Temporarily make the entire region writable for patching
    pal::pal_virtual_memory_protect(dll_base, dll_size, pal::PalProt::READ_WRITE_EXEC)?;

    for entry in &patches.entries {
        let offset = entry.target_offset as usize;
        if offset + entry.replacement_bytes.len() > dll_size {
            eprintln!(
                "Warning: Patch at offset 0x{:x} exceeds DLL bounds, skipping",
                offset
            );
            continue;
        }

        // Verify original bytes match (if we have them)
        if !entry.original_bytes.is_empty() {
            let actual = unsafe {
                std::slice::from_raw_parts(dll_base.add(offset), entry.original_bytes.len())
            };
            if actual != entry.original_bytes.as_slice() {
                eprintln!(
                    "Warning: Original bytes mismatch at 0x{:x}: expected {:?}, got {:?}",
                    offset, entry.original_bytes, actual
                );
                // Still apply the patch - the binary might be a different version
            }
        }

        // Apply the patch
        if !entry.replacement_bytes.is_empty() {
            unsafe {
                std::ptr::copy_nonoverlapping(
                    entry.replacement_bytes.as_ptr(),
                    dll_base.add(offset),
                    entry.replacement_bytes.len(),
                );
            }
            applied.push(entry.clone());
        }
    }

    Ok(applied)
}

/// Scan a directory for NTUM components and report what's available
pub fn scan_ntum_directory(dir: &Path) -> Result<NtumInventory> {
    let mut inventory = NtumInventory {
        directory: dir.to_path_buf(),
        kernel_binary: None,
        kernel_ini: None,
        ntdll: None,
        ntdll_dbpatch: None,
        win32k: None,
        win32k_dbpatch: None,
        registry_hive: None,
        manifest: None,
        other_dlls: Vec::new(),
        other_dbpatches: Vec::new(),
    };

    if !dir.exists() {
        bail!("NTUM directory does not exist: {}", dir.display());
    }

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();

        if name.contains("ntoskrnl") && name.ends_with(".bin") {
            inventory.kernel_binary = Some(path.clone());
        } else if name.contains("ntoskrnl") && name.ends_with(".bin.ini") {
            inventory.kernel_ini = Some(path.clone());
        } else if name == "ntdll.dll" {
            inventory.ntdll = Some(path.clone());
        } else if name == "ntdll.dll.dbpatch" {
            inventory.ntdll_dbpatch = Some(path.clone());
        } else if name.starts_with("win32k") && name.ends_with(".sys") {
            inventory.win32k = Some(path.clone());
        } else if name.starts_with("win32k") && name.ends_with(".dbpatch") {
            inventory.win32k_dbpatch = Some(path.clone());
        } else if name == "windows.hiv" {
            inventory.registry_hive = Some(path.clone());
        } else if name.ends_with(".dbmanifest") {
            inventory.manifest = Some(path.clone());
        } else if name.ends_with(".dll") || name.ends_with(".sys") {
            inventory.other_dlls.push(path.clone());
        } else if name.ends_with(".dbpatch") {
            inventory.other_dbpatches.push(path.clone());
        }
    }

    Ok(inventory)
}

/// Inventory of NTUM components found in a directory
#[derive(Debug, Serialize)]
pub struct NtumInventory {
    pub directory: PathBuf,
    pub kernel_binary: Option<PathBuf>,
    pub kernel_ini: Option<PathBuf>,
    pub ntdll: Option<PathBuf>,
    pub ntdll_dbpatch: Option<PathBuf>,
    pub win32k: Option<PathBuf>,
    pub win32k_dbpatch: Option<PathBuf>,
    pub registry_hive: Option<PathBuf>,
    pub manifest: Option<PathBuf>,
    pub other_dlls: Vec<PathBuf>,
    pub other_dbpatches: Vec<PathBuf>,
}

impl NtumInventory {
    pub fn is_complete(&self) -> bool {
        self.kernel_binary.is_some() && self.ntdll.is_some()
    }

    pub fn summary(&self) -> String {
        let mut parts: Vec<String> = Vec::new();

        if self.kernel_binary.is_some() {
            parts.push("ntoskrnl.dll.bin [OK]".to_string());
        } else {
            parts.push("ntoskrnl.dll.bin [MISSING]".to_string());
        }

        if self.ntdll.is_some() {
            parts.push("ntdll.dll [OK]".to_string());
        } else {
            parts.push("ntdll.dll [MISSING]".to_string());
        }

        if self.ntdll_dbpatch.is_some() {
            parts.push("ntdll.dll.dbpatch [OK]".to_string());
        } else {
            parts.push("ntdll.dll.dbpatch [MISSING]".to_string());
        }

        parts.push(format!("{} additional DLLs", self.other_dlls.len()));

        parts.join(", ")
    }
}
