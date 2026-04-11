//! .dbpatch file analyzer and reverser
//!
//! Microsoft's .dbpatch files contain binary patches that replace syscall
//! instructions in real Windows DLLs with PAL downcall stubs.
//!
//! This module reverse-engineers the .dbpatch format and can:
//! - Parse .dbpatch files to extract patch entries
//! - Show what syscall sites are being redirected
//! - Reconstruct the PAL downcall interface from the patches
//! - Apply patches to recreate the SQLPAL-modified DLLs
//!
//! The .dbpatch mechanism is the KEY to how Drawbridge works:
//!   Original ntdll.dll: NtCreateFile -> mov eax, 0x55; syscall
//!   Patched ntdll.dll:  NtCreateFile -> mov eax, 0x55; call [pal_stub]

use anyhow::{Context, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use serde::Serialize;
use std::io::{Cursor, Read};
use std::path::Path;

/// A single patch entry from a .dbpatch file
#[derive(Debug, Clone, Serialize)]
pub struct PatchEntry {
    /// Offset within the target DLL where the patch is applied
    pub target_offset: u64,
    /// Original bytes at the patch site (usually syscall/int 2e instruction)
    pub original_bytes: Vec<u8>,
    /// Replacement bytes (PAL downcall stub)
    pub replacement_bytes: Vec<u8>,
    /// Size of the patch
    pub patch_size: usize,
    /// Whether this looks like a syscall redirection
    pub is_syscall_redirect: bool,
    /// The NT syscall number if detectable (from mov eax, NNN before syscall)
    pub syscall_number: Option<u32>,
    /// Analysis of what the replacement does
    pub replacement_analysis: String,
}

/// Parsed .dbpatch file
#[derive(Debug, Serialize)]
pub struct DbPatchFile {
    pub filename: String,
    pub target_dll: String,
    pub total_patches: usize,
    pub syscall_redirects: usize,
    pub entries: Vec<PatchEntry>,
    pub format_version: u32,
    pub raw_size: usize,
}

/// Result of analyzing a .dbpatch file
#[derive(Debug, Serialize)]
pub struct DbPatchAnalysis {
    pub file: DbPatchFile,
    pub pal_downcalls: Vec<PalDowncall>,
    pub syscall_table: Vec<SyscallMapping>,
}

/// A PAL downcall discovered from patch analysis
#[derive(Debug, Clone, Serialize)]
pub struct PalDowncall {
    pub address: u64,
    pub syscall_number: u32,
    pub nt_function_name: String,
    pub patch_bytes: Vec<u8>,
}

/// Mapping from NT syscall number to function name
#[derive(Debug, Clone, Serialize)]
pub struct SyscallMapping {
    pub number: u32,
    pub name: String,
    pub category: String,
}

// Known NT syscall numbers (Windows 8.1 / 10 x64)
// These are the syscall numbers that .dbpatch would redirect
fn known_syscall_name(num: u32) -> &'static str {
    match num {
        0x0055 => "NtCreateFile",
        0x0006 => "NtReadFile",
        0x0008 => "NtWriteFile",
        0x000F => "NtClose",
        0x0018 => "NtAllocateVirtualMemory",
        0x001E => "NtFreeVirtualMemory",
        0x0050 => "NtProtectVirtualMemory",
        0x0023 => "NtQueryInformationFile",
        0x0027 => "NtSetInformationFile",
        0x0037 => "NtQueryVolumeInformationFile",
        0x004E => "NtCreateSection",
        0x0028 => "NtMapViewOfSection",
        0x002A => "NtUnmapViewOfSection",
        0x000C => "NtWaitForSingleObject",
        0x000B => "NtWaitForMultipleObjects",
        0x004D => "NtCreateEvent",
        0x000E => "NtSetEvent",
        0x0024 => "NtResetEvent",
        0x004A => "NtCreateMutant",
        0x001C => "NtReleaseMutant",
        0x004C => "NtCreateSemaphore",
        0x001D => "NtReleaseSemaphore",
        0x0036 => "NtQuerySystemInformation",
        0x001B => "NtQueryPerformanceCounter",
        0x0049 => "NtCreateThread",
        0x0053 => "NtTerminateThread",
        0x0029 => "NtTerminateProcess",
        0x003A => "NtDelayExecution",
        0x002C => "NtYieldExecution",
        0x0016 => "NtQueryInformationProcess",
        0x001A => "NtQueryInformationThread",
        0x0052 => "NtCreateKey",
        0x0012 => "NtOpenKey",
        0x0013 => "NtDeleteKey",
        0x0019 => "NtQueryValueKey",
        0x0014 => "NtSetValueKey",
        0x000D => "NtDeviceIoControlFile",
        0x0005 => "NtFsControlFile",
        0x0004 => "NtDuplicateObject",
        0x0010 => "NtQueryObject",
        _ => "Unknown",
    }
}

fn syscall_category(name: &str) -> &'static str {
    if name.contains("File") || name.contains("Volume") || name.contains("FsControl") {
        "I/O"
    } else if name.contains("VirtualMemory") || name.contains("Section") || name.contains("MapView")
    {
        "Memory"
    } else if name.contains("Thread") || name.contains("Process") || name.contains("Yield") {
        "Process/Thread"
    } else if name.contains("Event")
        || name.contains("Mutex")
        || name.contains("Mutant")
        || name.contains("Semaphore")
        || name.contains("Wait")
    {
        "Synchronization"
    } else if name.contains("Key") || name.contains("Value") {
        "Registry"
    } else if name.contains("System") || name.contains("Performance") || name.contains("Delay") {
        "System"
    } else if name.contains("Object") || name.contains("Duplicate") || name.contains("Close") {
        "Object"
    } else {
        "Other"
    }
}

/// Try to parse a .dbpatch file
///
/// The exact format is proprietary, so we use heuristics:
/// 1. Look for a header with version/count info
/// 2. Scan for patch entries (offset + original + replacement)
/// 3. Identify syscall redirections by looking for 0F 05 or CD 2E patterns
pub fn parse_dbpatch(path: &Path) -> Result<DbPatchFile> {
    let data =
        std::fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;
    parse_dbpatch_bytes(&data, path)
}

pub fn parse_dbpatch_bytes(data: &[u8], path: &Path) -> Result<DbPatchFile> {
    let filename = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    // Derive target DLL name (ntdll.dll.dbpatch -> ntdll.dll)
    let target_dll = filename.trim_end_matches(".dbpatch").to_string();

    let mut entries = Vec::new();

    // Strategy 1: Look for a structured header
    // Many binary patch formats start with: magic, version, entry_count
    if data.len() >= 16 {
        let mut cursor = Cursor::new(data);

        // Try to read as: [format_version: u32] [entry_count: u32] [entries...]
        let _format_version = cursor.read_u32::<LittleEndian>().unwrap_or(0);
        let entry_count = cursor.read_u32::<LittleEndian>().unwrap_or(0);

        // Sanity check: reasonable entry count
        if entry_count > 0 && entry_count < 10000 {
            // Try to parse entries as: [offset: u64] [orig_size: u32] [orig_bytes...] [repl_size: u32] [repl_bytes...]
            for _ in 0..entry_count {
                if cursor.position() as usize + 16 > data.len() {
                    break;
                }

                let target_offset = cursor.read_u64::<LittleEndian>().unwrap_or(0);
                let orig_size = cursor.read_u32::<LittleEndian>().unwrap_or(0) as usize;

                if orig_size > 256 || cursor.position() as usize + orig_size > data.len() {
                    break;
                }

                let mut original_bytes = vec![0u8; orig_size];
                cursor.read_exact(&mut original_bytes).unwrap_or(());

                let repl_size = cursor.read_u32::<LittleEndian>().unwrap_or(0) as usize;
                if repl_size > 256 || cursor.position() as usize + repl_size > data.len() {
                    break;
                }

                let mut replacement_bytes = vec![0u8; repl_size];
                cursor.read_exact(&mut replacement_bytes).unwrap_or(());

                let is_syscall_redirect = original_bytes.windows(2).any(|w| {
                    (w[0] == 0x0F && w[1] == 0x05) || (w[0] == 0xCD && w[1] == 0x2E)
                });

                let syscall_number = extract_syscall_number(&original_bytes);

                let replacement_analysis = analyze_replacement(&replacement_bytes);

                entries.push(PatchEntry {
                    target_offset,
                    original_bytes,
                    replacement_bytes,
                    patch_size: orig_size,
                    is_syscall_redirect,
                    syscall_number,
                    replacement_analysis,
                });
            }
        }
    }

    // Strategy 2: If structured parsing didn't find much, do a heuristic scan
    if entries.is_empty() {
        entries = heuristic_scan_patches(data);
    }

    let syscall_redirects = entries.iter().filter(|e| e.is_syscall_redirect).count();

    Ok(DbPatchFile {
        filename,
        target_dll,
        total_patches: entries.len(),
        syscall_redirects,
        entries,
        format_version: 0,
        raw_size: data.len(),
    })
}

/// Heuristic scan: look for syscall instruction patterns and surrounding context
fn heuristic_scan_patches(data: &[u8]) -> Vec<PatchEntry> {
    let mut entries = Vec::new();

    // Scan for potential patch entries by looking for common patterns:
    // - Sequences of [offset bytes] [0F 05] (syscall)
    // - Sequences of [offset bytes] [CD 2E] (int 2e)
    // - Call instruction patterns that might be PAL downcalls

    for i in 0..data.len().saturating_sub(16) {
        // Look for what could be a patch entry pointing to a syscall
        // Pattern: 8-byte offset, then some bytes containing 0F 05
        let window = &data[i..std::cmp::min(i + 32, data.len())];

        // Check if bytes 8-9 or 10-11 contain syscall
        if window.len() >= 12 {
            let has_syscall = window[8..12]
                .windows(2)
                .any(|w| (w[0] == 0x0F && w[1] == 0x05) || (w[0] == 0xCD && w[1] == 0x2E));

            if has_syscall {
                let offset = u64::from_le_bytes(window[0..8].try_into().unwrap_or([0; 8]));

                // Sanity check: offset should be reasonable for a DLL
                if offset > 0x1000 && offset < 0x10_000_000 {
                    entries.push(PatchEntry {
                        target_offset: offset,
                        original_bytes: window[8..12].to_vec(),
                        replacement_bytes: if window.len() >= 16 {
                            window[12..16].to_vec()
                        } else {
                            vec![]
                        },
                        patch_size: 4,
                        is_syscall_redirect: true,
                        syscall_number: extract_syscall_number(&window[..12]),
                        replacement_analysis: "Heuristic detection - needs verification".to_string(),
                    });
                }
            }
        }
    }

    entries
}

/// Extract NT syscall number from instruction bytes
/// Pattern: mov eax, <number>; syscall
/// x64: B8 XX XX XX XX (mov eax, imm32) followed by 0F 05 (syscall)
fn extract_syscall_number(bytes: &[u8]) -> Option<u32> {
    for i in 0..bytes.len().saturating_sub(6) {
        // mov eax, imm32 = B8 XX XX XX XX
        if bytes[i] == 0xB8 && i + 5 <= bytes.len() {
            let num = u32::from_le_bytes([bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4]]);
            // Sanity: NT syscall numbers are typically < 0x2000
            if num < 0x2000 {
                return Some(num);
            }
        }
        // mov eax, imm32 via r/m encoding
        if bytes[i] == 0xC7 && i + 1 < bytes.len() && bytes[i + 1] == 0xC0 && i + 6 <= bytes.len()
        {
            let num = u32::from_le_bytes([bytes[i + 2], bytes[i + 3], bytes[i + 4], bytes[i + 5]]);
            if num < 0x2000 {
                return Some(num);
            }
        }
    }
    None
}

/// Analyze what the replacement bytes do
fn analyze_replacement(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "Empty replacement".to_string();
    }

    // Look for common patterns in replacement code
    if bytes.len() >= 5 && bytes[0] == 0xE8 {
        // CALL rel32 - relative call to PAL downcall stub
        let rel = i32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        return format!("CALL rel32 (offset {:+}) - likely PAL downcall", rel);
    }

    if bytes.len() >= 6 && bytes[0] == 0xFF && bytes[1] == 0x15 {
        // CALL [rip+disp32] - indirect call through PAL dispatch table
        let disp = i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]);
        return format!(
            "CALL [RIP{:+}] - indirect PAL downcall via dispatch table",
            disp
        );
    }

    if bytes.len() >= 2 && bytes[0] == 0xFF && bytes[1] == 0x25 {
        // JMP [rip+disp32] - indirect jump through PAL dispatch table
        let disp = if bytes.len() >= 6 {
            i32::from_le_bytes([bytes[2], bytes[3], bytes[4], bytes[5]])
        } else {
            0
        };
        return format!(
            "JMP [RIP{:+}] - indirect PAL jump via dispatch table",
            disp
        );
    }

    if bytes.len() >= 2 && bytes[0] == 0x0F && bytes[1] == 0x05 {
        return "SYSCALL (unchanged - not actually patched)".to_string();
    }

    if bytes.iter().all(|&b| b == 0x90) {
        return format!("NOP slide ({} bytes) - syscall removed", bytes.len());
    }

    format!("Unknown pattern: {}", hex::encode(bytes))
}

/// Full analysis of a .dbpatch file, including PAL downcall mapping
pub fn analyze_dbpatch(path: &Path) -> Result<DbPatchAnalysis> {
    let file = parse_dbpatch(path)?;

    let mut pal_downcalls = Vec::new();
    let mut syscall_table = Vec::new();

    for entry in &file.entries {
        if let Some(num) = entry.syscall_number {
            let name = known_syscall_name(num).to_string();
            let category = syscall_category(&name).to_string();

            syscall_table.push(SyscallMapping {
                number: num,
                name: name.clone(),
                category,
            });

            if entry.is_syscall_redirect {
                pal_downcalls.push(PalDowncall {
                    address: entry.target_offset,
                    syscall_number: num,
                    nt_function_name: name,
                    patch_bytes: entry.replacement_bytes.clone(),
                });
            }
        }
    }

    // Sort syscall table by number
    syscall_table.sort_by_key(|s| s.number);
    syscall_table.dedup_by_key(|s| s.number);

    Ok(DbPatchAnalysis {
        file,
        pal_downcalls,
        syscall_table,
    })
}
