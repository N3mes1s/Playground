//! PAL Downcall Mapper
//!
//! Maps the complete PAL interface by analyzing:
//! - .dbpatch files (NT syscall -> PAL redirections)
//! - ntdll.dll exports (NT API surface)
//! - ntoskrnl.dll.bin structure (NTUM kernel)
//! - Gramine PAL comparison (open-source reference)
//!
//! Produces a complete map of: NT API -> PAL downcall -> Linux syscall
//!
//! Usage:
//!   pal-map --ntum-dir ./extracted/ntum
//!   pal-map --report
//!   pal-map --gramine-compare

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use drawbridge_poc::{dbpatch, ntum, pal, pe};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "pal-map")]
#[command(about = "Map the complete PAL downcall interface")]
struct Args {
    /// Directory containing extracted NTUM files
    #[arg(long)]
    ntum_dir: Option<PathBuf>,

    /// Show PAL status report
    #[arg(long)]
    report: bool,

    /// Compare with Gramine's PAL
    #[arg(long)]
    gramine_compare: bool,

    /// Output as JSON
    #[arg(long)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Always show PAL report
    if args.report || args.ntum_dir.is_none() {
        show_pal_report(args.json)?;
    }

    if args.gramine_compare {
        show_gramine_comparison()?;
    }

    if let Some(ntum_dir) = &args.ntum_dir {
        analyze_ntum_pal(ntum_dir, args.json)?;
    }

    Ok(())
}

fn show_pal_report(json: bool) -> Result<()> {
    pal::pal_init()?;
    let report = pal::pal_report();

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("{}", "=".repeat(70));
    println!("{}", "PAL Status Report (Linux Host)".bold().cyan());
    println!("{}", "=".repeat(70));
    println!("  Host OS:       {}", report.host_os);
    println!("  Kernel:        {}", report.kernel_version);
    println!("  CPUs:          {}", report.cpu_count);
    println!(
        "  Total Memory:  {:.1} GB",
        report.total_memory as f64 / (1024.0 * 1024.0 * 1024.0)
    );
    println!("  Page Size:     {} bytes", report.page_size);

    println!();
    println!("  {}", "Implemented PAL Operations:".bold());
    for (i, op) in report.operations_implemented.iter().enumerate() {
        println!("    [{:>2}] {}", i + 1, op.green());
    }
    println!();
    println!(
        "  Total: {} operations implemented",
        report.operations_implemented.len()
    );

    Ok(())
}

fn show_gramine_comparison() -> Result<()> {
    println!();
    println!("{}", "=".repeat(70));
    println!(
        "{}",
        "PAL Comparison: Our Implementation vs Gramine".bold().cyan()
    );
    println!("{}", "=".repeat(70));

    // Gramine's full PAL surface (from our research)
    let gramine_ops = vec![
        ("Memory", vec![
            ("PalVirtualMemoryAlloc", "mmap", true),
            ("PalVirtualMemoryFree", "munmap", true),
            ("PalVirtualMemoryProtect", "mprotect", true),
            ("PalSetMemoryBookkeepingUpcalls", "N/A", false),
            ("PalDeviceMap", "mmap(fd)", false),
        ]),
        ("Process", vec![
            ("PalProcessCreate", "vfork+execve", false),
            ("PalProcessExit", "exit_group", true),
        ]),
        ("Streams", vec![
            ("PalStreamOpen", "open", true),
            ("PalStreamRead", "read/pread64", true),
            ("PalStreamWrite", "write/pwrite64", true),
            ("PalStreamDelete", "unlink/rmdir", false),
            ("PalStreamSetLength", "ftruncate", false),
            ("PalStreamFlush", "fsync", false),
            ("PalStreamAttributesQuery", "stat", false),
            ("PalStreamAttributesQueryByHandle", "fstat", false),
            ("PalStreamAttributesSetByHandle", "fchmod", false),
            ("PalStreamChangeName", "rename", false),
            ("PalStreamWaitForClient", "accept", false),
        ]),
        ("Sockets", vec![
            ("PalSocketCreate", "socket", false),
            ("PalSocketBind", "bind", false),
            ("PalSocketListen", "listen", false),
            ("PalSocketAccept", "accept4", false),
            ("PalSocketConnect", "connect", false),
            ("PalSocketSend", "sendmsg", false),
            ("PalSocketRecv", "recvmsg", false),
        ]),
        ("Threads", vec![
            ("PalThreadCreate", "clone", true),
            ("PalThreadYieldExecution", "sched_yield", false),
            ("PalThreadExit", "exit", true),
            ("PalThreadResume", "tkill", false),
            ("PalThreadSetCpuAffinity", "sched_setaffinity", false),
            ("PalThreadGetCpuAffinity", "sched_getaffinity", false),
        ]),
        ("Sync", vec![
            ("PalEventCreate", "eventfd", true),
            ("PalEventSet", "eventfd_write", false),
            ("PalEventClear", "eventfd_read", false),
            ("PalEventWait", "ppoll", false),
            ("PalStreamsWaitEvents", "ppoll", false),
        ]),
        ("IPC", vec![
            ("PalSendHandle", "sendmsg(SCM_RIGHTS)", false),
            ("PalReceiveHandle", "recvmsg(SCM_RIGHTS)", false),
        ]),
        ("Time/System", vec![
            ("PalSystemTimeQuery", "clock_gettime", true),
            ("PalRandomBitsRead", "getrandom", true),
            ("PalCpuIdRetrieve", "cpuid insn", false),
            ("PalSegmentBaseGet", "arch_prctl", false),
            ("PalSegmentBaseSet", "arch_prctl", false),
        ]),
        ("Exception", vec![
            ("PalSetExceptionHandler", "rt_sigaction", false),
        ]),
        ("Object", vec![
            ("PalObjectDestroy", "close", false),
        ]),
    ];

    let mut total = 0;
    let mut implemented = 0;

    for (category, ops) in &gramine_ops {
        println!();
        println!("  {}:", category.bold());
        println!(
            "    {:<40} {:<20} {}",
            "Gramine PAL".bold(),
            "Linux Syscall".bold(),
            "Our PAL".bold()
        );

        for (name, syscall, we_have_it) in ops {
            total += 1;
            if *we_have_it {
                implemented += 1;
            }

            let status = if *we_have_it {
                "IMPLEMENTED".green().bold()
            } else {
                "TODO".red()
            };

            println!("    {:<40} {:<20} {}", name, syscall, status);
        }
    }

    println!();
    println!("{}", "-".repeat(70));
    println!(
        "  Coverage: {}/{} ({:.0}%)",
        implemented,
        total,
        (implemented as f64 / total as f64) * 100.0
    );
    println!(
        "  {}",
        "Missing operations are straightforward Linux syscall wrappers".dimmed()
    );

    Ok(())
}

fn analyze_ntum_pal(ntum_dir: &PathBuf, json: bool) -> Result<()> {
    println!();
    println!("{}", "=".repeat(70));
    println!(
        "{}: {}",
        "NTUM PAL Analysis".bold().cyan(),
        ntum_dir.display().to_string().yellow()
    );
    println!("{}", "=".repeat(70));

    // Scan for NTUM components
    let inventory = ntum::scan_ntum_directory(ntum_dir)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&inventory)?);
        return Ok(());
    }

    println!("  {}", "NTUM Inventory:".bold());
    println!(
        "    Kernel binary:   {}",
        inventory
            .kernel_binary
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "NOT FOUND".red().to_string())
    );
    println!(
        "    Kernel .ini:     {}",
        inventory
            .kernel_ini
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "NOT FOUND".red().to_string())
    );
    println!(
        "    ntdll.dll:       {}",
        inventory
            .ntdll
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "NOT FOUND".red().to_string())
    );
    println!(
        "    ntdll.dbpatch:   {}",
        inventory
            .ntdll_dbpatch
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "NOT FOUND".red().to_string())
    );
    println!("    Other DLLs:      {}", inventory.other_dlls.len());
    println!("    Other .dbpatch:  {}", inventory.other_dbpatches.len());

    // If ntdll.dbpatch exists, analyze it
    if let Some(ref dbpatch_path) = inventory.ntdll_dbpatch {
        println!();
        println!("  {}", "Analyzing ntdll.dll.dbpatch...".bold());

        match dbpatch::analyze_dbpatch(dbpatch_path) {
            Ok(analysis) => {
                println!("    Patches found:    {}", analysis.file.total_patches);
                println!("    Syscall redirects: {}", analysis.file.syscall_redirects);
                println!("    PAL downcalls:     {}", analysis.pal_downcalls.len());

                if !analysis.syscall_table.is_empty() {
                    println!();
                    println!(
                        "    {}",
                        "Reconstructed NT Syscall -> PAL Map:".bold().green()
                    );
                    for mapping in &analysis.syscall_table {
                        println!(
                            "      0x{:04x} {} [{}]",
                            mapping.number,
                            mapping.name.yellow(),
                            mapping.category
                        );
                    }
                }
            }
            Err(e) => {
                eprintln!("    Failed to analyze .dbpatch: {}", e);
            }
        }
    }

    // If ntdll.dll exists, analyze it
    if let Some(ref ntdll_path) = inventory.ntdll {
        println!();
        println!("  {}", "Analyzing ntdll.dll PE...".bold());

        match pe::analyze_pe(ntdll_path) {
            Ok(analysis) => {
                println!("    Exports: {}", analysis.exports.len());
                println!("    Syscall sites: {}", analysis.syscall_sites.len());

                // Show Nt* exports (these are the NT API surface)
                let nt_exports: Vec<_> = analysis
                    .exports
                    .iter()
                    .filter(|e| e.name.starts_with("Nt") || e.name.starts_with("Zw"))
                    .collect();

                if !nt_exports.is_empty() {
                    println!(
                        "    NT API functions: {} (Nt*/Zw*)",
                        nt_exports.len()
                    );
                    println!();
                    println!(
                        "    {}",
                        "These are the functions that .dbpatch redirects to PAL:".dimmed()
                    );
                    for (_i, exp) in nt_exports.iter().enumerate().take(30) {
                        println!("      {} (rva=0x{:08x})", exp.name.yellow(), exp.rva);
                    }
                    if nt_exports.len() > 30 {
                        println!("      ... and {} more", nt_exports.len() - 30);
                    }
                }
            }
            Err(e) => {
                eprintln!("    Failed to analyze ntdll.dll: {}", e);
            }
        }
    }

    // Show kernel .ini if available
    if let Some(ref ini_path) = inventory.kernel_ini {
        println!();
        println!("  {}", "Kernel Memory Layout (.bin.ini):".bold());

        match ntum::parse_bin_ini(ini_path) {
            Ok(layout) => {
                println!("    Base address: 0x{:016x}", layout.base_address);
                println!("    Total size:   0x{:x}", layout.total_size);

                for section in &layout.sections {
                    println!(
                        "    Section {}: VA=0x{:x} Size=0x{:x} Prot={}",
                        section.name, section.virtual_address, section.size, section.protection
                    );
                }
            }
            Err(e) => {
                eprintln!("    Failed to parse .bin.ini: {}", e);
            }
        }
    }

    // Overall assessment
    println!();
    println!("{}", "=".repeat(70));
    println!("{}", "Assessment".bold().cyan());
    println!("{}", "=".repeat(70));

    if inventory.is_complete() {
        println!(
            "  {} NTUM components are present and can be loaded",
            "READY:".green().bold()
        );
        println!("  Run: drawbridge-poc --ntum-dir {} --exe <target.exe>", ntum_dir.display());
    } else {
        println!(
            "  {} NTUM components are incomplete",
            "INCOMPLETE:".yellow().bold()
        );
        println!("  Extract from SQL Server on Linux:");
        println!("    ./scripts/extract_ntum.sh");
    }

    Ok(())
}
