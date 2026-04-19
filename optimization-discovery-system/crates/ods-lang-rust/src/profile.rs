//! Subprocess-based profiler for the Rust adapter.
//!
//! We don't link against `libbpf` or `perf_event_open` here; instead we shell
//! out to tools that are available in practice on a CI runner:
//!
//! * `/usr/bin/time -v` for wall clock + max RSS
//! * `strace -c`        for syscall frequency (on Linux)
//! * `perf stat`        for cycles / instructions / cache-miss (when
//!                      `CAP_PERFMON` or `kernel.perf_event_paranoid` allows)
//!
//! Each of these is optional; missing tools cause the corresponding fields to
//! remain `None` rather than failing the whole run. The stage-2 eBPF path can
//! be introduced as a parallel implementation without changing callers.

use anyhow::Result;
use ods_core::TargetSig;
use ods_exec::{run, which, Invocation};
use ods_lang::ProfileReport;
use regex::Regex;
use std::path::Path;
use std::time::Duration;

/// Profile a target by invoking `cargo bench --bench <name>` under the
/// available observability tools.  Returns an aggregate [`ProfileReport`].
pub async fn profile_target(workdir: &Path, target: &TargetSig) -> Result<ProfileReport> {
    // Build the command we want to profile.  We treat the target's symbol as
    // the criterion filter so users can name any hot primitive.
    let bench_args = vec![
        "bench".to_string(),
        "--workspace".to_string(),
        "--".to_string(),
        target.symbol.clone(),
    ];

    let mut report = ProfileReport {
        wall: Duration::ZERO,
        cycles: None,
        instructions: None,
        llc_misses: None,
        branch_misses: None,
        syscall_counts: vec![],
        alloc_count: None,
        alloc_bytes: None,
        flame_svg_path: None,
    };

    // Wall clock via `/usr/bin/time -v` (always-available on Linux CI runners;
    // falls back silently when the util isn't present).
    if let Some(bin) = which("time").or_else(|| which("/usr/bin/time")) {
        let inv = Invocation::new(bin.display().to_string())
            .arg("-v")
            .arg("cargo")
            .args(bench_args.clone())
            .cwd(workdir)
            .timeout(Duration::from_secs(900))
            .allow_nonzero();
        if let Ok(out) = run(&inv).await {
            if let Some(wall) = parse_time_elapsed(&out.stderr) {
                report.wall = wall;
            }
        }
    }

    // Syscall counts via `strace -c -f`.
    if let Some(bin) = which("strace") {
        let inv = Invocation::new(bin.display().to_string())
            .args(["-c".to_string(), "-f".to_string(), "cargo".to_string()])
            .args(bench_args.clone())
            .cwd(workdir)
            .timeout(Duration::from_secs(900))
            .allow_nonzero();
        if let Ok(out) = run(&inv).await {
            report.syscall_counts = parse_strace_c(&out.stderr);
        }
    }

    // CPU counters via `perf stat`.
    if let Some(bin) = which("perf") {
        let inv = Invocation::new(bin.display().to_string())
            .args(
                [
                    "stat",
                    "-e",
                    "cycles,instructions,LLC-load-misses,branch-misses",
                    "cargo",
                ]
                .map(String::from),
            )
            .args(bench_args.clone())
            .cwd(workdir)
            .timeout(Duration::from_secs(900))
            .allow_nonzero();
        if let Ok(out) = run(&inv).await {
            fill_perf_stat(&mut report, &out.stderr);
        }
    }

    Ok(report)
}

fn parse_time_elapsed(stderr: &str) -> Option<Duration> {
    // GNU time prints: "Elapsed (wall clock) time (h:mm:ss or m:ss): 0:12.34"
    // The label contains colons, so we anchor on the final ": <digits>" pair.
    let re = Regex::new(r"Elapsed \(wall clock\).*?:\s*([0-9]+(?::[0-9.]+)*(?:\.[0-9]+)?)").ok()?;
    let caps = re.captures(stderr)?;
    let raw = caps.get(1)?.as_str();
    let parts: Vec<&str> = raw.split(':').collect();
    let seconds: f64 = match parts.len() {
        1 => parts[0].parse().ok()?,
        2 => {
            let m: f64 = parts[0].parse().ok()?;
            let s: f64 = parts[1].parse().ok()?;
            m * 60.0 + s
        }
        3 => {
            let h: f64 = parts[0].parse().ok()?;
            let m: f64 = parts[1].parse().ok()?;
            let s: f64 = parts[2].parse().ok()?;
            h * 3600.0 + m * 60.0 + s
        }
        _ => return None,
    };
    Some(Duration::from_secs_f64(seconds))
}

fn parse_strace_c(stderr: &str) -> Vec<(String, u64)> {
    // `strace -c` table rows:  "  0.00  0.000000           0         5        1 read"
    let re =
        Regex::new(r"(?m)^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+\d*\s*([a-zA-Z0-9_]+)\s*$").unwrap();
    let mut out = Vec::new();
    for caps in re.captures_iter(stderr) {
        let calls: u64 = caps
            .get(1)
            .and_then(|m| m.as_str().parse().ok())
            .unwrap_or(0);
        let name = caps.get(2).unwrap().as_str().to_string();
        if name == "total" {
            continue;
        }
        out.push((name, calls));
    }
    out
}

fn fill_perf_stat(report: &mut ProfileReport, stderr: &str) {
    let re =
        Regex::new(r"(?m)^\s*([\d,\.]+)\s+(cycles|instructions|LLC-load-misses|branch-misses)")
            .unwrap();
    for caps in re.captures_iter(stderr) {
        let raw = caps.get(1).unwrap().as_str().replace(',', "");
        let Ok(n) = raw.parse::<f64>() else {
            continue;
        };
        let n = n as u64;
        match caps.get(2).unwrap().as_str() {
            "cycles" => report.cycles = Some(n),
            "instructions" => report.instructions = Some(n),
            "LLC-load-misses" => report.llc_misses = Some(n),
            "branch-misses" => report.branch_misses = Some(n),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_gnu_time_elapsed_min_sec() {
        let s = "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:12.34\n";
        let d = parse_time_elapsed(s).unwrap();
        assert!((d.as_secs_f64() - 12.34).abs() < 0.01);
    }

    #[test]
    fn parses_strace_table() {
        let s = "\
% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 42.00    0.001234          0       100              read
 33.00    0.000987          0        50         5   openat
------ ----------- ----------- --------- --------- ----------------
100.00    0.002221                  150         5   total
";
        let counts = parse_strace_c(s);
        let m: std::collections::HashMap<_, _> = counts.into_iter().collect();
        assert_eq!(m["read"], 100);
        assert_eq!(m["openat"], 50);
        assert!(!m.contains_key("total"));
    }

    #[test]
    fn parses_perf_stat_counters() {
        let stderr = "\
 Performance counter stats for 'cargo bench foo':

        1,234,567      cycles
          765,432      instructions
           12,345      LLC-load-misses
              321      branch-misses
";
        let mut r = ProfileReport {
            wall: Duration::ZERO,
            cycles: None,
            instructions: None,
            llc_misses: None,
            branch_misses: None,
            syscall_counts: vec![],
            alloc_count: None,
            alloc_bytes: None,
            flame_svg_path: None,
        };
        fill_perf_stat(&mut r, stderr);
        assert_eq!(r.cycles, Some(1_234_567));
        assert_eq!(r.instructions, Some(765_432));
        assert_eq!(r.llc_misses, Some(12_345));
        assert_eq!(r.branch_misses, Some(321));
    }
}
