use clap::Parser;
use sysinfo_service::{format_bytes, format_kb, format_uptime, SysInfo};

#[derive(Parser)]
#[command(name = "sysinfo-service", version, about = "OS system information service")]
struct Cli {
    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Output as compact JSON (single line)
    #[arg(long)]
    compact: bool,
}

fn main() {
    let cli = Cli::parse();

    let info = match SysInfo::collect() {
        Ok(info) => info,
        Err(e) => {
            eprintln!("Error collecting system info: {e}");
            std::process::exit(1);
        }
    };

    if cli.json || cli.compact {
        let output = if cli.compact {
            serde_json::to_string(&info)
        } else {
            serde_json::to_string_pretty(&info)
        };
        match output {
            Ok(json) => println!("{json}"),
            Err(e) => {
                eprintln!("Error serializing to JSON: {e}");
                std::process::exit(1);
            }
        }
        return;
    }

    // Human-readable report
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║              SYSTEM INFORMATION REPORT              ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!();

    println!("  Hostname:       {}", info.hostname);
    println!("  Kernel:         {}", info.kernel_version);
    println!("  Uptime:         {}", format_uptime(info.uptime_seconds));
    println!();

    println!("── CPU ──────────────────────────────────────────────");
    println!("  Model:          {}", info.cpu.model);
    println!("  Cores:          {}", info.cpu.cores);
    println!();

    println!("── Memory ──────────────────────────────────────────");
    println!("  Total:          {}", format_kb(info.memory.total_kb));
    println!("  Available:      {}", format_kb(info.memory.available_kb));
    println!("  Used:           {}", format_kb(info.memory.used_kb));
    println!("  Buffers:        {}", format_kb(info.memory.buffers_kb));
    println!("  Cached:         {}", format_kb(info.memory.cached_kb));
    println!(
        "  Usage:          {:.1}%",
        info.memory.usage_percent
    );
    println!();

    println!("── Load Average ────────────────────────────────────");
    println!(
        "  1/5/15 min:     {:.2} / {:.2} / {:.2}",
        info.load_average.one_min, info.load_average.five_min, info.load_average.fifteen_min
    );
    println!(
        "  Tasks:          {} running / {} total",
        info.load_average.running_tasks, info.load_average.total_tasks
    );
    println!("  Processes:      {} (total forks since boot)", info.process_count);
    println!();

    if !info.disks.is_empty() {
        println!("── Disk I/O ────────────────────────────────────────");
        for d in &info.disks {
            println!(
                "  {:<10}  reads: {:>8}  writes: {:>8}  read: {:>10}  written: {:>10}",
                d.device,
                d.reads_completed,
                d.writes_completed,
                format_bytes(d.read_sectors * 512),
                format_bytes(d.write_sectors * 512),
            );
        }
        println!();
    }

    if !info.network_interfaces.is_empty() {
        println!("── Network Interfaces ──────────────────────────────");
        for iface in &info.network_interfaces {
            println!(
                "  {:<12}  RX: {:>10} ({} pkts, {} err)  TX: {:>10} ({} pkts, {} err)",
                iface.name,
                format_bytes(iface.rx_bytes),
                iface.rx_packets,
                iface.rx_errors,
                format_bytes(iface.tx_bytes),
                iface.tx_packets,
                iface.tx_errors,
            );
        }
        println!();
    }

    println!("═══════════════════════════════════════════════════════");
}
