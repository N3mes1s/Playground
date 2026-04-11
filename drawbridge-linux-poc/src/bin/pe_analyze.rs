//! PE Binary Analyzer
//!
//! Analyzes Windows PE files for Drawbridge relevance:
//! - Import/export tables
//! - Syscall instruction sites (targets for .dbpatch)
//! - Drawbridge component classification
//!
//! Usage:
//!   pe-analyze ntdll.dll
//!   pe-analyze sqlservr.exe --json
//!   pe-analyze ./extracted/*.dll --syscalls-only

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use drawbridge_poc::pe;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pe-analyze")]
#[command(about = "Analyze PE binaries for Drawbridge relevance")]
struct Args {
    /// PE files to analyze
    files: Vec<PathBuf>,

    /// Show only files with syscall instructions
    #[arg(long)]
    syscalls_only: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Show full import/export tables
    #[arg(long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.files.is_empty() {
        eprintln!("Usage: pe-analyze <file.dll> [file2.exe] ...");
        std::process::exit(1);
    }

    let mut analyses = Vec::new();

    for path in &args.files {
        match pe::analyze_pe(path) {
            Ok(analysis) => {
                if args.syscalls_only && analysis.syscall_sites.is_empty() {
                    continue;
                }
                analyses.push(analysis);
            }
            Err(e) => {
                eprintln!(
                    "{}: {} - {}",
                    "SKIP".yellow(),
                    path.display(),
                    e
                );
            }
        }
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&analyses)?);
        return Ok(());
    }

    for analysis in &analyses {
        println!("{}", "=".repeat(70));
        println!(
            "{}: {}",
            "PE Analysis".bold().cyan(),
            analysis.filename.bold()
        );
        println!("{}", "=".repeat(70));

        // Basic info
        println!("  Machine:       {}", analysis.machine);
        println!("  64-bit:        {}", analysis.is_64bit);
        println!("  DLL:           {}", analysis.is_dll);
        println!("  Image Base:    0x{:016x}", analysis.image_base);
        println!("  Entry Point:   0x{:08x}", analysis.entry_point);
        println!("  Size of Image: 0x{:x}", analysis.size_of_image);
        println!("  Relocatable:   {}", analysis.has_relocations);

        // Drawbridge relevance
        let dr = &analysis.drawbridge_relevance;
        println!();
        println!("  {}", "Drawbridge Relevance:".bold());
        println!(
            "    NTUM Component:   {}",
            if dr.is_ntum_component {
                "YES".red().bold()
            } else {
                "no".dimmed()
            }
        );
        println!(
            "    Library OS:       {}",
            if dr.is_library_os {
                "YES".yellow().bold()
            } else {
                "no".dimmed()
            }
        );
        println!(
            "    Needs .dbpatch:   {}",
            if dr.needs_dbpatch {
                format!("YES ({} syscall sites)", analysis.syscall_sites.len())
                    .red()
                    .bold()
            } else {
                "no".dimmed()
            }
        );
        println!("    PAL Dependency:   {}", dr.pal_dependency_level);

        for note in &dr.notes {
            println!("    Note: {}", note.dimmed());
        }

        // Sections
        println!();
        println!("  {}", "Sections:".bold());
        println!(
            "    {:<10} {:>12} {:>12} {:>5}",
            "Name", "VirtAddr", "Size", "Prot"
        );
        for section in &analysis.sections {
            let prot = format!(
                "{}{}{}",
                if section.is_readable { "r" } else { "-" },
                if section.is_writable { "w" } else { "-" },
                if section.is_executable { "x" } else { "-" },
            );
            println!(
                "    {:<10} 0x{:08x}   {:>10} {:>5}",
                section.name,
                section.virtual_address,
                section.virtual_size,
                prot
            );
        }

        // Imports (summary)
        if !analysis.imports.is_empty() {
            println!();
            println!("  {}", "Imports:".bold());
            for import in &analysis.imports {
                let marker = if import.is_ntdll {
                    " [NTDLL - NTUM CORE]".red().bold().to_string()
                } else if import.is_kernel32 {
                    " [kernel32 - Win32 API]".yellow().to_string()
                } else if import.has_nt_syscalls {
                    " [has Nt* imports]".yellow().to_string()
                } else {
                    String::new()
                };

                println!(
                    "    {} ({} functions){}",
                    import.dll_name.cyan(),
                    import.functions.len(),
                    marker
                );

                if args.verbose {
                    for func in &import.functions {
                        let func_marker = if func.starts_with("Nt") || func.starts_with("Zw") {
                            " <-- NT syscall".red().to_string()
                        } else {
                            String::new()
                        };
                        println!("      {}{}", func, func_marker);
                    }
                }
            }
        }

        // Exports (summary)
        if !analysis.exports.is_empty() {
            println!();
            println!("  {} ({} total)", "Exports:".bold(), analysis.exports.len());
            if args.verbose {
                for export in &analysis.exports {
                    println!(
                        "    [{:>5}] 0x{:08x} {}",
                        export.ordinal, export.rva, export.name
                    );
                }
            } else {
                // Show first 10
                for export in analysis.exports.iter().take(10) {
                    println!("    {} (ordinal {})", export.name, export.ordinal);
                }
                if analysis.exports.len() > 10 {
                    println!("    ... and {} more", analysis.exports.len() - 10);
                }
            }
        }

        // Syscall sites
        if !analysis.syscall_sites.is_empty() {
            println!();
            println!(
                "  {} ({} found)",
                "Syscall Instruction Sites:".bold().red(),
                analysis.syscall_sites.len()
            );
            println!(
                "    {}",
                "These are the locations .dbpatch needs to redirect to PAL"
                    .dimmed()
            );
            for (i, site) in analysis.syscall_sites.iter().enumerate().take(20) {
                println!(
                    "    [{:>3}] offset=0x{:08x} rva=0x{:08x} {} {}",
                    i,
                    site.offset,
                    site.rva,
                    site.instruction.red(),
                    site.nearby_function.dimmed()
                );
                if args.verbose {
                    println!("          context: {}", site.context.dimmed());
                }
            }
            if analysis.syscall_sites.len() > 20 {
                println!(
                    "    ... and {} more",
                    analysis.syscall_sites.len() - 20
                );
            }
        }

        println!();
    }

    // Summary
    if analyses.len() > 1 {
        println!("{}", "=".repeat(70));
        println!("{}", "Summary".bold().cyan());
        println!("{}", "=".repeat(70));
        println!("  Analyzed:         {} files", analyses.len());
        println!(
            "  NTUM components:  {}",
            analyses
                .iter()
                .filter(|a| a.drawbridge_relevance.is_ntum_component)
                .count()
        );
        println!(
            "  Need .dbpatch:    {}",
            analyses
                .iter()
                .filter(|a| a.drawbridge_relevance.needs_dbpatch)
                .count()
        );
        println!(
            "  Total syscalls:   {}",
            analyses
                .iter()
                .map(|a| a.syscall_sites.len())
                .sum::<usize>()
        );
    }

    Ok(())
}
