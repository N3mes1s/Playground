//! PE/COFF binary analyzer
//!
//! Analyzes Windows PE (Portable Executable) files extracted from SQLPAL's
//! SFP archives. Uses goblin for parsing and provides Drawbridge-specific
//! analysis: import tables, syscall sites, PAL downcall candidates.

use anyhow::{Context, Result};
use goblin::pe::PE;
use serde::Serialize;
use std::path::Path;

/// Analyzed PE binary
#[derive(Debug, Serialize)]
pub struct PeAnalysis {
    pub filename: String,
    pub machine: String,
    pub is_64bit: bool,
    pub is_dll: bool,
    pub image_base: u64,
    pub entry_point: u64,
    pub size_of_image: u64,
    pub sections: Vec<SectionInfo>,
    pub imports: Vec<ImportInfo>,
    pub exports: Vec<ExportInfo>,
    pub has_relocations: bool,
    pub syscall_sites: Vec<SyscallSite>,
    pub drawbridge_relevance: DrawbridgeRelevance,
}

#[derive(Debug, Serialize)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_address: u64,
    pub virtual_size: u64,
    pub raw_size: u64,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

#[derive(Debug, Serialize)]
pub struct ImportInfo {
    pub dll_name: String,
    pub functions: Vec<String>,
    pub is_ntdll: bool,
    pub is_kernel32: bool,
    pub has_nt_syscalls: bool,
}

#[derive(Debug, Serialize)]
pub struct ExportInfo {
    pub name: String,
    pub ordinal: u32,
    pub rva: u64,
}

/// A location in the binary where a syscall instruction exists
#[derive(Debug, Serialize)]
pub struct SyscallSite {
    pub offset: u64,
    pub rva: u64,
    pub instruction: String,
    pub nearby_function: String,
    pub context: String,
}

/// How relevant this PE is to Drawbridge/SQLPAL
#[derive(Debug, Serialize)]
pub struct DrawbridgeRelevance {
    pub is_ntum_component: bool,
    pub is_library_os: bool,
    pub needs_dbpatch: bool,
    pub pal_dependency_level: String,
    pub notes: Vec<String>,
}

/// Analyze a PE binary
pub fn analyze_pe(path: &Path) -> Result<PeAnalysis> {
    let data = std::fs::read(path).with_context(|| format!("Failed to read: {}", path.display()))?;
    analyze_pe_bytes(&data, path.file_name().unwrap_or_default().to_string_lossy().to_string())
}

/// Analyze PE from raw bytes
pub fn analyze_pe_bytes(data: &[u8], filename: String) -> Result<PeAnalysis> {
    let pe = PE::parse(data).with_context(|| format!("Failed to parse PE: {}", filename))?;

    let is_64bit = pe.is_64;
    let machine = match pe.header.coff_header.machine {
        0x8664 => "x86_64".to_string(),
        0x014c => "i386".to_string(),
        0xaa64 => "ARM64".to_string(),
        other => format!("0x{:04x}", other),
    };

    let is_dll = pe.is_lib;

    let (image_base, entry_point, size_of_image) = if let Some(opt) = pe.header.optional_header {
        let std = opt.standard_fields;
        let win = opt.windows_fields;
        (
            win.image_base,
            std.address_of_entry_point as u64,
            win.size_of_image as u64,
        )
    } else {
        (0, 0, 0)
    };

    // Sections
    let sections: Vec<SectionInfo> = pe
        .sections
        .iter()
        .map(|s| {
            let name = String::from_utf8_lossy(
                &s.name[..s.name.iter().position(|&b| b == 0).unwrap_or(s.name.len())],
            )
            .to_string();
            SectionInfo {
                name,
                virtual_address: s.virtual_address as u64,
                virtual_size: s.virtual_size as u64,
                raw_size: s.size_of_raw_data as u64,
                characteristics: s.characteristics,
                is_executable: s.characteristics & 0x2000_0000 != 0,
                is_writable: s.characteristics & 0x8000_0000 != 0,
                is_readable: s.characteristics & 0x4000_0000 != 0,
            }
        })
        .collect();

    // Imports
    let imports: Vec<ImportInfo> = pe
        .imports
        .iter()
        .fold(
            std::collections::HashMap::<String, Vec<String>>::new(),
            |mut map, imp| {
                map.entry(imp.dll.to_string())
                    .or_default()
                    .push(imp.name.to_string());
                map
            },
        )
        .into_iter()
        .map(|(dll_name, functions)| {
            let dll_lower = dll_name.to_lowercase();
            let is_ntdll = dll_lower.contains("ntdll");
            let is_kernel32 = dll_lower.contains("kernel32");
            let has_nt_syscalls = functions.iter().any(|f| {
                f.starts_with("Nt") || f.starts_with("Zw") || f.starts_with("Rtl")
            });
            ImportInfo {
                dll_name,
                functions,
                is_ntdll,
                is_kernel32,
                has_nt_syscalls,
            }
        })
        .collect();

    // Exports
    let exports: Vec<ExportInfo> = pe
        .exports
        .iter()
        .filter_map(|e| {
            e.name.map(|name| ExportInfo {
                name: name.to_string(),
                ordinal: e.offset.unwrap_or(0) as u32,
                rva: e.rva as u64,
            })
        })
        .collect();

    let has_relocations = pe.header.optional_header
        .map(|oh| {
            oh.data_directories
                .get_base_relocation_table()
                .is_some()
        })
        .unwrap_or(false);

    // Scan for syscall instructions in executable sections
    let syscall_sites = find_syscall_sites(data, &sections);

    // Determine Drawbridge relevance
    let drawbridge_relevance = assess_drawbridge_relevance(
        &filename,
        &imports,
        &exports,
        &syscall_sites,
    );

    Ok(PeAnalysis {
        filename,
        machine,
        is_64bit,
        is_dll,
        image_base,
        entry_point,
        size_of_image,
        sections,
        imports,
        exports,
        has_relocations,
        syscall_sites,
        drawbridge_relevance,
    })
}

/// Scan executable sections for syscall/int 2e instructions
fn find_syscall_sites(data: &[u8], sections: &[SectionInfo]) -> Vec<SyscallSite> {
    let mut sites = Vec::new();

    for section in sections {
        if !section.is_executable {
            continue;
        }

        let start = section.virtual_address as usize;
        let end = (start + section.raw_size as usize).min(data.len());
        if start >= data.len() {
            continue;
        }

        let section_data = &data[start..end];

        // Look for syscall instruction (0x0F 0x05)
        for i in 0..section_data.len().saturating_sub(1) {
            if section_data[i] == 0x0F && section_data[i + 1] == 0x05 {
                let rva = section.virtual_address + i as u64;
                let offset = start as u64 + i as u64;

                // Get context bytes around the syscall
                let ctx_start = i.saturating_sub(16);
                let ctx_end = (i + 8).min(section_data.len());
                let context = hex::encode(&section_data[ctx_start..ctx_end]);

                sites.push(SyscallSite {
                    offset,
                    rva,
                    instruction: "syscall (0F 05)".to_string(),
                    nearby_function: format!("in section {}", section.name),
                    context,
                });
            }

            // Look for int 0x2e (CD 2E) - legacy NT syscall
            if section_data[i] == 0xCD && section_data[i + 1] == 0x2E {
                let rva = section.virtual_address + i as u64;
                let offset = start as u64 + i as u64;

                let ctx_start = i.saturating_sub(16);
                let ctx_end = (i + 8).min(section_data.len());
                let context = hex::encode(&section_data[ctx_start..ctx_end]);

                sites.push(SyscallSite {
                    offset,
                    rva,
                    instruction: "int 0x2e (CD 2E)".to_string(),
                    nearby_function: format!("in section {}", section.name),
                    context,
                });
            }
        }
    }

    sites
}

/// Assess how relevant a PE binary is to the Drawbridge architecture
fn assess_drawbridge_relevance(
    filename: &str,
    imports: &[ImportInfo],
    exports: &[ExportInfo],
    syscall_sites: &[SyscallSite],
) -> DrawbridgeRelevance {
    let fl = filename.to_lowercase();
    let mut notes = Vec::new();

    let is_ntum_component = fl.contains("ntoskrnl")
        || fl.contains("ntdll")
        || fl.contains("win32k")
        || fl.contains("hal.");

    let is_library_os = is_ntum_component
        || fl.contains("kernel32")
        || fl.contains("user32")
        || fl.contains("gdi32")
        || fl.contains("kerberos")
        || fl.contains("schannel");

    let needs_dbpatch = !syscall_sites.is_empty();

    let pal_dependency_level = if is_ntum_component {
        if needs_dbpatch {
            notes.push(format!(
                "Contains {} syscall sites that need PAL redirection (.dbpatch)",
                syscall_sites.len()
            ));
        }
        "CRITICAL - Core NTUM, directly calls PAL".to_string()
    } else if is_library_os {
        notes.push("Library OS DLL - calls through ntdll, indirect PAL dependency".to_string());
        "HIGH - Library OS component".to_string()
    } else if imports.iter().any(|i| i.is_ntdll) {
        notes.push("Imports from ntdll.dll - uses NT native API".to_string());
        "MEDIUM - NT API consumer".to_string()
    } else if imports.iter().any(|i| i.is_kernel32) {
        notes.push("Imports from kernel32.dll - standard Win32 app".to_string());
        "LOW - Standard Win32 application".to_string()
    } else {
        "NONE - No Windows API dependency detected".to_string()
    };

    // Count NT syscall imports
    let nt_import_count: usize = imports
        .iter()
        .filter(|i| i.has_nt_syscalls)
        .map(|i| i.functions.len())
        .sum();

    if nt_import_count > 0 {
        notes.push(format!("Imports {} Nt*/Zw*/Rtl* functions", nt_import_count));
    }

    // Check for specific SQLPAL-relevant exports
    let sqlpal_exports: Vec<&str> = exports
        .iter()
        .filter_map(|e| {
            let name = &e.name;
            if name.contains("Pal")
                || name.contains("Sql")
                || name.contains("SOS")
                || name.contains("SQLOS")
            {
                Some(name.as_str())
            } else {
                None
            }
        })
        .collect();

    if !sqlpal_exports.is_empty() {
        notes.push(format!(
            "SQLPAL-relevant exports: {}",
            sqlpal_exports.join(", ")
        ));
    }

    DrawbridgeRelevance {
        is_ntum_component,
        is_library_os,
        needs_dbpatch,
        pal_dependency_level,
        notes,
    }
}
