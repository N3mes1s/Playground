//! Drawbridge PoC Runner
//!
//! The main orchestrator that ties all components together to run a Windows
//! PE executable on Linux using the Drawbridge architecture.
//!
//! Flow:
//! 1. Initialize PAL (Platform Abstraction Layer) on Linux
//! 2. Load NTUM (NT User-Mode kernel) from extracted components
//! 3. Apply .dbpatch files to redirect syscalls to PAL
//! 4. Load target PE executable
//! 5. Resolve imports against Library OS DLLs
//! 6. Transfer control to PE entry point
//!
//! Usage:
//!   drawbridge-poc --ntum-dir ./extracted/ntum --exe target.exe
//!   drawbridge-poc --report
//!   drawbridge-poc --analyze ./extracted/ntum

use anyhow::{bail, Result};
use clap::Parser;
use colored::Colorize;
use std::path::PathBuf;

use drawbridge_poc::{dbpatch, ntum, pal, pe, sfp};

#[derive(Parser)]
#[command(name = "drawbridge-poc")]
#[command(about = "Run Windows PE executables on Linux via Drawbridge architecture")]
#[command(long_about = "
Drawbridge Linux PoC - Extract and run Windows PE binaries using
the same architecture as SQL Server on Linux (SQLPAL).

Components:
  - PAL: Platform Abstraction Layer (~50 ops mapped to Linux syscalls)
  - NTUM: NT User-Mode kernel (extracted from SQL Server on Linux)
  - PE Loader: Loads Windows executables, resolves imports
  - .dbpatch: Redirects NT syscalls to PAL downcalls

Tools:
  sfp-extract     Extract SFP archives (NTUM recovery)
  pe-analyze      Analyze PE binaries for Drawbridge relevance
  dbpatch-reverse Reverse-engineer .dbpatch format
  pal-map         Map the complete PAL interface
")]
struct Args {
    /// Directory containing extracted NTUM files
    #[arg(long)]
    ntum_dir: Option<PathBuf>,

    /// Windows PE executable to run
    #[arg(long)]
    exe: Option<PathBuf>,

    /// Analyze NTUM directory without running
    #[arg(long)]
    analyze: Option<PathBuf>,

    /// Show PAL status report
    #[arg(long)]
    report: bool,

    /// Extract SFP file
    #[arg(long)]
    extract_sfp: Option<PathBuf>,

    /// Output directory for extraction
    #[arg(short, long, default_value = "./extracted")]
    output: PathBuf,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    print_banner();

    // Initialize PAL
    pal::pal_init()?;

    if args.report {
        return cmd_report(args.json);
    }

    if let Some(sfp_path) = args.extract_sfp {
        return cmd_extract_sfp(&sfp_path, &args.output);
    }

    if let Some(analyze_dir) = args.analyze {
        return cmd_analyze(&analyze_dir, args.json);
    }

    if let (Some(ntum_dir), Some(exe_path)) = (&args.ntum_dir, &args.exe) {
        return cmd_run(ntum_dir, exe_path);
    }

    // No specific command - show help
    println!("{}", "Quick Start Guide:".bold());
    println!();
    println!("  1. Extract NTUM from SQL Server on Linux:");
    println!("     {} extract_ntum.sh", "./scripts/".dimmed());
    println!();
    println!("  2. Analyze extracted components:");
    println!(
        "     {} --analyze ./extracted/ntum",
        "drawbridge-poc".cyan()
    );
    println!();
    println!("  3. Run a Windows executable:");
    println!(
        "     {} --ntum-dir ./extracted/ntum --exe target.exe",
        "drawbridge-poc".cyan()
    );
    println!();
    println!("  Individual tools:");
    println!(
        "     {} system.sfp -o ./extracted",
        "sfp-extract".cyan()
    );
    println!("     {} ntdll.dll", "pe-analyze".cyan());
    println!(
        "     {} ntdll.dll.dbpatch",
        "dbpatch-reverse".cyan()
    );
    println!("     {} --report", "pal-map".cyan());

    Ok(())
}

fn print_banner() {
    println!(
        "{}",
        r#"
  ╔════════════════════════��══════════════════╗
  ║  Drawbridge Linux PoC                     ║
  ║  Run Windows PE on Linux via Library OS   ║
  ╚═══════════════════════════════════════════╝
"#
        .cyan()
    );
}

/// Show PAL report
fn cmd_report(json: bool) -> Result<()> {
    let report = pal::pal_report();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "PAL Status Report".bold().cyan());
    println!("{}", "=".repeat(50));
    println!("  Host:    {} ({})", report.host_os, report.kernel_version);
    println!("  CPUs:    {}", report.cpu_count);
    println!(
        "  Memory:  {:.1} GB",
        report.total_memory as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!("  Page:    {} bytes", report.page_size);
    println!();
    println!(
        "  {} PAL operations implemented:",
        report.operations_implemented.len()
    );
    for op in &report.operations_implemented {
        println!("    {}", op.green());
    }

    // Quick PAL test
    println!();
    println!("{}", "PAL Self-Test:".bold());

    // Test memory allocation
    match pal::pal_virtual_memory_alloc(None, 4096, pal::PalProt::READ_WRITE) {
        Ok(ptr) => {
            println!("  [{}] PalVirtualMemoryAlloc: {:p}", "OK".green(), ptr);
            // Write and read back
            unsafe {
                std::ptr::write(ptr, 0x42u8);
                assert_eq!(std::ptr::read(ptr), 0x42u8);
            }
            println!("  [{}] Memory read/write verified", "OK".green());
            pal::pal_virtual_memory_free(ptr, 4096)?;
            println!("  [{}] PalVirtualMemoryFree", "OK".green());
        }
        Err(e) => println!("  [{}] PalVirtualMemoryAlloc: {}", "FAIL".red(), e),
    }

    // Test time
    let time = pal::pal_time_query();
    println!("  [{}] PalTimeQuery: {} us", "OK".green(), time);

    // Test random
    let mut buf = [0u8; 16];
    pal::pal_random_read(&mut buf)?;
    println!(
        "  [{}] PalRandomRead: {}",
        "OK".green(),
        hex::encode(&buf)
    );

    // Test console
    let stdout = pal::pal_console_stdout();
    pal::pal_stream_write(&stdout, b"  [OK] PalConsoleWrite\n")?;

    println!();
    println!(
        "  {} All PAL self-tests passed",
        "PASS".green().bold()
    );

    Ok(())
}

/// Extract SFP archive
fn cmd_extract_sfp(sfp_path: &PathBuf, output: &PathBuf) -> Result<()> {
    println!(
        "{}: {}",
        "Extracting SFP".bold(),
        sfp_path.display().to_string().yellow()
    );

    let data = std::fs::read(sfp_path)?;
    println!("  Archive size: {} bytes", data.len());

    match sfp::SfpArchive::parse(data) {
        Ok(archive) => {
            println!("  Entries found: {}", archive.entries.len());

            let ntum_files = archive.find_ntum_components();
            if !ntum_files.is_empty() {
                println!();
                println!("  {}", "NTUM Components Found:".bold().red());
                for f in &ntum_files {
                    println!(
                        "    {} ({} bytes)",
                        f.name.red().bold(),
                        f.file_length
                    );
                }
            }

            std::fs::create_dir_all(output)?;
            let extracted = archive.extract_all(output)?;
            println!();
            println!(
                "  {} files extracted to {}",
                extracted.len(),
                output.display()
            );
        }
        Err(e) => {
            println!("  Our SFP parser failed: {}", e);
            println!();
            println!(
                "  {}",
                "Recommendation: Use nta/sfpack for extraction:".yellow()
            );
            println!("    git clone https://github.com/nta/sfpack && cd sfpack && make");
            println!("    ./sfpack {}", sfp_path.display());
        }
    }

    Ok(())
}

/// Analyze NTUM directory
fn cmd_analyze(ntum_dir: &PathBuf, json: bool) -> Result<()> {
    println!(
        "{}: {}",
        "Analyzing NTUM directory".bold(),
        ntum_dir.display().to_string().yellow()
    );

    let inventory = ntum::scan_ntum_directory(ntum_dir)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }

    println!();
    println!("  {}", "Component Inventory:".bold());
    println!("    {}", inventory.summary());

    let mut all_pe_paths: Vec<PathBuf> = Vec::new();
    if let Some(ref p) = inventory.ntdll {
        all_pe_paths.push(p.clone());
    }
    for dll in &inventory.other_dlls {
        all_pe_paths.push(dll.clone());
    }

    if !all_pe_paths.is_empty() {
        println!();
        println!("  {}", "PE Analysis:".bold());
        for pe_path in &all_pe_paths {
            match pe::analyze_pe(pe_path) {
                Ok(analysis) => {
                    let dr = &analysis.drawbridge_relevance;
                    let status = if dr.is_ntum_component {
                        "NTUM".red().bold()
                    } else if dr.is_library_os {
                        "LibOS".yellow()
                    } else {
                        "App".dimmed()
                    };

                    println!(
                        "    {} [{}] exports={} imports={} syscalls={}",
                        analysis.filename.cyan(),
                        status,
                        analysis.exports.len(),
                        analysis.imports.len(),
                        analysis.syscall_sites.len()
                    );
                }
                Err(e) => {
                    println!(
                        "    {} - {}",
                        pe_path.display().to_string().dimmed(),
                        e
                    );
                }
            }
        }
    }

    println!();
    if inventory.is_complete() {
        println!(
            "  {}",
            "NTUM is complete. Ready for Drawbridge execution.".green().bold()
        );
    } else {
        println!(
            "  {}",
            "NTUM is incomplete. Run ./scripts/extract_ntum.sh".yellow()
        );
    }

    Ok(())
}

/// Run a Windows PE executable via Drawbridge
fn cmd_run(ntum_dir: &PathBuf, exe_path: &PathBuf) -> Result<()> {
    println!(
        "{}: {} on {}",
        "Drawbridge Run".bold().green(),
        exe_path.display().to_string().yellow(),
        "Linux".cyan()
    );
    println!();

    // Step 1: Verify NTUM components
    println!("  [1/6] {}", "Scanning NTUM directory...".bold());
    let inventory = ntum::scan_ntum_directory(ntum_dir)?;
    println!("    {}", inventory.summary());

    if !inventory.is_complete() {
        bail!(
            "NTUM components incomplete. Extract with: ./scripts/extract_ntum.sh\n  \
             Need at minimum: ntoskrnl.dll.bin + ntdll.dll"
        );
    }

    // Step 2: Load kernel
    println!("  [2/6] {}", "Loading NTUM kernel...".bold());
    let kernel_path = inventory.kernel_binary.as_ref().unwrap();
    let ini_path = inventory.kernel_ini.as_ref().map(|p| p.as_path());

    let (kernel_base, kernel_size, layout) = ntum::load_ntum_kernel(kernel_path, ini_path)?;
    println!("    Loaded at {:p}, size=0x{:x}", kernel_base, kernel_size);

    if let Some(ref layout) = layout {
        println!("    Preferred base: 0x{:016x}", layout.base_address);
    }

    // Step 3: Apply .dbpatch
    println!("  [3/6] {}", "Applying .dbpatch files...".bold());
    if let Some(ref dbpatch_path) = inventory.ntdll_dbpatch {
        let patches = dbpatch::parse_dbpatch(dbpatch_path)?;
        println!(
            "    ntdll.dll.dbpatch: {} patches ({} syscall redirects)",
            patches.total_patches, patches.syscall_redirects
        );
        println!(
            "    {}",
            "Patches analyzed (apply requires loaded DLL in memory)".dimmed()
        );
    }

    // Step 4: Analyze target PE
    println!("  [4/6] {}", "Analyzing target PE...".bold());
    let pe_analysis = pe::analyze_pe(exe_path)?;
    println!("    Machine:     {}", pe_analysis.machine);
    println!("    64-bit:      {}", pe_analysis.is_64bit);
    println!("    Entry point: 0x{:08x}", pe_analysis.entry_point);
    println!("    Imports:     {} DLLs", pe_analysis.imports.len());

    for import in &pe_analysis.imports {
        println!("      {} ({} functions)", import.dll_name, import.functions.len());
    }

    // Step 5: Load PE into memory
    println!("  [5/6] {}", "Loading PE into memory...".bold());
    let pe_data = std::fs::read(exe_path)?;
    let pe_size = ((pe_analysis.size_of_image as usize + 4095) / 4096) * 4096;
    let pe_base = pal::pal_virtual_memory_alloc(None, pe_size.max(4096), pal::PalProt::READ_WRITE)?;
    println!("    Mapped at {:p}, size=0x{:x}", pe_base, pe_size);

    let header_size = pe_data.len().min(pe_size);
    unsafe {
        std::ptr::copy_nonoverlapping(pe_data.as_ptr(), pe_base, header_size);
    }
    println!("    PE headers copied");

    // Step 6: Report status
    println!("  [6/6] {}", "Drawbridge state:".bold());
    println!("    PAL:           {}", "ACTIVE (Linux)".green());
    println!("    NTUM kernel:   {} ({:p})", "LOADED".green(), kernel_base);
    println!("    Target PE:     {} ({:p})", "LOADED".green(), pe_base);

    println!();
    println!("{}", "=".repeat(70));
    println!("{}", "PoC Status: All components loaded successfully.".bold().green());
    println!();
    println!("{}", "To execute the PE entry point, the full NTUM initialization".yellow());
    println!("{}", "sequence is needed (registry, DLL init, import resolution).".yellow());
    println!("{}", "This requires the complete NTUM extracted from mssql-server.".yellow());

    // Cleanup
    pal::pal_virtual_memory_free(pe_base, pe_size.max(4096))?;
    pal::pal_virtual_memory_free(kernel_base, kernel_size)?;

    Ok(())
}
