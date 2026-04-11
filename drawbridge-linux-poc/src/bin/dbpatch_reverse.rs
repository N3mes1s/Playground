//! .dbpatch Reverse Engineering Tool
//!
//! Reverse-engineers Microsoft's .dbpatch binary patch format to understand
//! how SQLPAL redirects NT syscalls to PAL downcalls.
//!
//! Usage:
//!   dbpatch-reverse ntdll.dll.dbpatch
//!   dbpatch-reverse ntdll.dll.dbpatch --with-dll ntdll.dll
//!   dbpatch-reverse *.dbpatch --json

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use drawbridge_poc::dbpatch;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "dbpatch-reverse")]
#[command(about = "Reverse-engineer .dbpatch files to map PAL downcall interface")]
struct Args {
    /// .dbpatch file(s) to analyze
    files: Vec<PathBuf>,

    /// Path to the target DLL (for cross-referencing patch sites)
    #[arg(long)]
    with_dll: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Show raw hex of each patch entry
    #[arg(long)]
    raw: bool,

    /// Only show syscall redirections
    #[arg(long)]
    syscalls_only: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.files.is_empty() {
        eprintln!("Usage: dbpatch-reverse <file.dbpatch> [file2.dbpatch] ...");
        std::process::exit(1);
    }

    let mut all_analyses = Vec::new();

    for path in &args.files {
        println!("{}", "=".repeat(70));
        println!(
            "{}: {}",
            ".dbpatch Analysis".bold().cyan(),
            path.display().to_string().yellow()
        );
        println!("{}", "=".repeat(70));

        let file_size = std::fs::metadata(path)?.len();
        println!("  File size: {} bytes", file_size);

        // Raw header dump
        if args.raw {
            let raw_data = std::fs::read(path)?;
            println!();
            println!("  {}", "Raw header (first 128 bytes):".bold());
            for (i, chunk) in raw_data[..128.min(raw_data.len())].chunks(16).enumerate() {
                print!("    {:08x}: ", i * 16);
                for byte in chunk {
                    print!("{:02x} ", byte);
                }
                for _ in chunk.len()..16 {
                    print!("   ");
                }
                print!(" |");
                for byte in chunk {
                    if byte.is_ascii_graphic() || *byte == b' ' {
                        print!("{}", *byte as char);
                    } else {
                        print!(".");
                    }
                }
                println!("|");
            }
        }

        match dbpatch::analyze_dbpatch(path) {
            Ok(analysis) => {
                println!();
                println!("  Target DLL:       {}", analysis.file.target_dll);
                println!("  Total patches:    {}", analysis.file.total_patches);
                println!(
                    "  Syscall redirects: {}",
                    analysis.file.syscall_redirects
                );
                println!(
                    "  PAL downcalls found: {}",
                    analysis.pal_downcalls.len()
                );

                // Syscall table
                if !analysis.syscall_table.is_empty() {
                    println!();
                    println!("  {}", "NT Syscall -> PAL Downcall Map:".bold().red());
                    println!(
                        "    {:<8} {:<35} {}",
                        "Syscall#".bold(),
                        "NT Function".bold(),
                        "Category".bold()
                    );
                    println!("    {}", "-".repeat(60));

                    for mapping in &analysis.syscall_table {
                        let name_colored = if mapping.name == "Unknown" {
                            format!("Unknown (0x{:04x})", mapping.number).dimmed().to_string()
                        } else {
                            mapping.name.yellow().to_string()
                        };

                        println!(
                            "    0x{:04x}   {:<35} {}",
                            mapping.number, name_colored, mapping.category
                        );
                    }
                }

                // Patch entries
                if !analysis.file.entries.is_empty() {
                    println!();
                    println!("  {}", "Patch Entries:".bold());

                    for (i, entry) in analysis.file.entries.iter().enumerate() {
                        if args.syscalls_only && !entry.is_syscall_redirect {
                            continue;
                        }

                        let syscall_marker = if entry.is_syscall_redirect {
                            " [SYSCALL REDIRECT]".red().bold().to_string()
                        } else {
                            String::new()
                        };

                        let syscall_info = if let Some(num) = entry.syscall_number {
                            let name = analysis
                                .syscall_table
                                .iter()
                                .find(|s| s.number == num)
                                .map(|s| s.name.as_str())
                                .unwrap_or("Unknown");
                            format!(" -> {} (0x{:04x})", name, num)
                                .yellow()
                                .to_string()
                        } else {
                            String::new()
                        };

                        println!(
                            "    [{:>4}] offset=0x{:08x} size={}{}{}",
                            i,
                            entry.target_offset,
                            entry.patch_size,
                            syscall_marker,
                            syscall_info
                        );

                        println!(
                            "           original: {}",
                            hex::encode(&entry.original_bytes).dimmed()
                        );
                        println!(
                            "           replace:  {}",
                            hex::encode(&entry.replacement_bytes).cyan()
                        );
                        println!(
                            "           analysis: {}",
                            entry.replacement_analysis.dimmed()
                        );
                    }
                }

                // PAL downcall summary
                if !analysis.pal_downcalls.is_empty() {
                    println!();
                    println!("{}", "  PAL Downcall Interface (Reconstructed):".bold().green());
                    println!("  {}", "This is the interface between NTUM and the PAL:".dimmed());
                    println!();

                    // Group by category
                    let mut by_category: std::collections::HashMap<&str, Vec<_>> =
                        std::collections::HashMap::new();
                    for downcall in &analysis.pal_downcalls {
                        let cat = analysis
                            .syscall_table
                            .iter()
                            .find(|s| s.number == downcall.syscall_number)
                            .map(|s| s.category.as_str())
                            .unwrap_or("Other");
                        by_category.entry(cat).or_default().push(downcall);
                    }

                    for (category, downcalls) in &by_category {
                        println!("    {}:", category.bold());
                        for dc in downcalls {
                            println!(
                                "      NT syscall 0x{:04x} ({}) at offset 0x{:x}",
                                dc.syscall_number,
                                dc.nt_function_name.yellow(),
                                dc.address
                            );
                        }
                    }
                }

                if args.json {
                    println!();
                    println!("{}", serde_json::to_string_pretty(&analysis)?);
                }

                all_analyses.push(analysis);
            }
            Err(e) => {
                eprintln!(
                    "  {} Failed to parse: {}",
                    "ERROR".red().bold(),
                    e
                );
                eprintln!("  The .dbpatch format is proprietary - our heuristic parser may not");
                eprintln!("  handle all variants. Try with --raw to see the raw bytes.");
            }
        }

        println!();
    }

    // Cross-reference with DLL if provided
    if let Some(dll_path) = &args.with_dll {
        println!("{}", "=".repeat(70));
        println!(
            "{}: {}",
            "Cross-Reference with DLL".bold().cyan(),
            dll_path.display().to_string().yellow()
        );
        println!("{}", "=".repeat(70));

        match drawbridge_poc::pe::analyze_pe(dll_path) {
            Ok(pe_analysis) => {
                println!(
                    "  DLL has {} syscall sites",
                    pe_analysis.syscall_sites.len()
                );

                let total_patches: usize = all_analyses.iter().map(|a| a.file.total_patches).sum();
                println!(
                    "  .dbpatch files contain {} total patches",
                    total_patches
                );

                // Check which syscall sites are covered by patches
                let patched_offsets: std::collections::HashSet<u64> = all_analyses
                    .iter()
                    .flat_map(|a| a.file.entries.iter().map(|e| e.target_offset))
                    .collect();

                let covered = pe_analysis
                    .syscall_sites
                    .iter()
                    .filter(|s| patched_offsets.contains(&s.offset))
                    .count();

                println!(
                    "  Syscall sites covered: {}/{}",
                    covered,
                    pe_analysis.syscall_sites.len()
                );

                let unpatched: Vec<_> = pe_analysis
                    .syscall_sites
                    .iter()
                    .filter(|s| !patched_offsets.contains(&s.offset))
                    .collect();

                if !unpatched.is_empty() {
                    println!();
                    println!(
                        "  {} ({}):",
                        "Unpatched syscall sites".bold().red(),
                        unpatched.len()
                    );
                    for site in &unpatched {
                        println!(
                            "    offset=0x{:08x} {} {}",
                            site.offset,
                            site.instruction.red(),
                            site.nearby_function.dimmed()
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("  Failed to analyze DLL: {}", e);
            }
        }
    }

    Ok(())
}
