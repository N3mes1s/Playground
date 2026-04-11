//! SFP Archive Extractor
//!
//! Extracts Microsoft's SFP (SQL Server Forge Pack) archives to recover
//! the Library OS (NTUM) and SQL Server binaries.
//!
//! Usage:
//!   sfp-extract /opt/mssql/lib/system.sfp -o ./extracted/ntum
//!   sfp-extract /opt/mssql/lib/sqlservr.sfp -o ./extracted/engine

use anyhow::{Context, Result};
use clap::Parser;
use colored::Colorize;
use drawbridge_poc::sfp;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sfp-extract")]
#[command(about = "Extract SFP archives from SQL Server on Linux (NTUM recovery)")]
struct Args {
    /// Path to the .sfp file
    sfp_path: PathBuf,

    /// Output directory for extracted files
    #[arg(short, long, default_value = "./extracted")]
    output: PathBuf,

    /// Only list contents, don't extract
    #[arg(short, long)]
    list: bool,

    /// Filter by file extension (e.g., "dll", "dbpatch")
    #[arg(short, long)]
    filter: Option<String>,

    /// Show NTUM-critical files only
    #[arg(long)]
    ntum_only: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!(
        "{} {}",
        "SFP Archive Extractor".bold().cyan(),
        "(Drawbridge NTUM Recovery)".dimmed()
    );
    println!();

    // Read the SFP file
    println!("Reading: {}", args.sfp_path.display().to_string().yellow());
    let data = std::fs::read(&args.sfp_path)
        .with_context(|| format!("Failed to read: {}", args.sfp_path.display()))?;
    println!("Size: {} bytes", data.len());

    // Parse header first
    println!();
    println!("{}", "SFP Header:".bold());
    let header = sfp::SfpHeader::parse(&data)?;
    println!("  Magic:            0x{:016x}", header.magic);
    println!("  Version:          {}", header.version);
    println!("  Dir table offset: 0x{:x}", header.first_dir_offset);
    println!("  Name table:       0x{:x}", header.name_table_offset);
    println!("  Data offset:      0x{:x}", header.data_offset);
    println!("  Archive size:     {}", header.archive_size);

    // Try full parse
    println!();
    println!("{}", "Parsing archive...".bold());
    match sfp::SfpArchive::parse(data) {
        Ok(archive) => {
            println!(
                "Found {} entries ({} files)",
                archive.entries.len(),
                archive.files.len()
            );
            println!();

            // List files
            let entries: Vec<_> = if args.ntum_only {
                archive.find_ntum_components().into_iter().collect()
            } else if let Some(ref ext) = args.filter {
                archive.find_by_extension(ext).into_iter().collect()
            } else {
                archive.entries.iter().collect()
            };

            if args.json {
                let json_data: Vec<_> = entries
                    .iter()
                    .map(|e| {
                        serde_json::json!({
                            "name": e.name,
                            "size": e.file_length,
                            "is_directory": e.is_directory,
                            "data_offset": e.data_start_offset,
                            "data_length": e.data_length,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&json_data)?);
            } else {
                println!(
                    "{:<50} {:>12} {:>4}",
                    "Name".bold(),
                    "Size".bold(),
                    "Type".bold()
                );
                println!("{}", "-".repeat(70));

                for entry in &entries {
                    let type_str = if entry.is_directory {
                        "DIR".blue()
                    } else {
                        "FILE".green()
                    };
                    let size_str = if entry.is_directory {
                        "-".to_string()
                    } else {
                        format_size(entry.file_length)
                    };

                    // Highlight NTUM-critical files
                    let name = &entry.name;
                    let name_colored = if is_ntum_critical(name) {
                        name.red().bold().to_string()
                    } else if name.ends_with(".dbpatch") {
                        name.yellow().to_string()
                    } else if name.ends_with(".dll") || name.ends_with(".sys") {
                        name.cyan().to_string()
                    } else {
                        name.to_string()
                    };

                    println!("{:<50} {:>12} {:>4}", name_colored, size_str, type_str);
                }

                println!();
                println!("Total: {} entries", entries.len());
            }

            // Extract if requested
            if !args.list {
                println!();
                println!(
                    "{}",
                    format!("Extracting to: {}", args.output.display()).bold()
                );
                std::fs::create_dir_all(&args.output)?;

                let extracted = archive.extract_all(&args.output)?;
                println!("Extracted {} files", extracted.len());

                // Highlight NTUM-critical files
                let critical: Vec<_> = extracted
                    .iter()
                    .filter(|p| {
                        is_ntum_critical(&p.file_name().unwrap_or_default().to_string_lossy())
                    })
                    .collect();

                if !critical.is_empty() {
                    println!();
                    println!("{}", "NTUM-Critical Files Found:".bold().red());
                    for f in critical {
                        println!("  {}", f.display().to_string().red());
                    }
                }
            }
        }
        Err(e) => {
            eprintln!("Failed to fully parse SFP archive: {}", e);
            eprintln!();
            eprintln!("{}", "Falling back to raw analysis...".yellow());

            // Show raw hex dump of the header area
            println!();
            println!("{}", "Raw header (first 256 bytes):".bold());
            let raw_data = std::fs::read(&args.sfp_path)?;
            for (i, chunk) in raw_data[..256.min(raw_data.len())].chunks(16).enumerate() {
                print!("  {:08x}: ", i * 16);
                for byte in chunk {
                    print!("{:02x} ", byte);
                }
                // ASCII representation
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

            eprintln!();
            eprintln!("Consider using sfpack (https://github.com/nta/sfpack) for extraction.");
            eprintln!("Our SFP parser is heuristic-based and may not handle all format variants.");
        }
    }

    Ok(())
}

fn is_ntum_critical(name: &str) -> bool {
    let n = name.to_lowercase();
    n.contains("ntoskrnl")
        || n.contains("ntdll")
        || n.contains("win32k")
        || n.contains("windows.hiv")
        || n.contains(".dbmanifest")
        || n.ends_with(".bin.ini")
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
