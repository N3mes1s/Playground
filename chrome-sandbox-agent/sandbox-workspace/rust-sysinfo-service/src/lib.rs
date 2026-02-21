use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SysInfoError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse {field}: {detail}")]
    Parse { field: String, detail: String },
}

type Result<T> = std::result::Result<T, SysInfoError>;

fn read_proc(path: &str) -> Result<String> {
    fs::read_to_string(path).map_err(|e| SysInfoError::ReadFile {
        path: path.to_string(),
        source: e,
    })
}

#[derive(Debug, Serialize)]
pub struct CpuInfo {
    pub model: String,
    pub cores: usize,
}

#[derive(Debug, Serialize)]
pub struct MemoryInfo {
    pub total_kb: u64,
    pub available_kb: u64,
    pub free_kb: u64,
    pub buffers_kb: u64,
    pub cached_kb: u64,
    pub used_kb: u64,
    pub usage_percent: f64,
}

#[derive(Debug, Serialize)]
pub struct LoadAverage {
    pub one_min: f64,
    pub five_min: f64,
    pub fifteen_min: f64,
    pub running_tasks: u32,
    pub total_tasks: u32,
}

#[derive(Debug, Serialize)]
pub struct DiskStat {
    pub device: String,
    pub reads_completed: u64,
    pub writes_completed: u64,
    pub read_sectors: u64,
    pub write_sectors: u64,
}

#[derive(Debug, Serialize)]
pub struct NetInterface {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Serialize)]
pub struct SysInfo {
    pub hostname: String,
    pub kernel_version: String,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub uptime_seconds: f64,
    pub load_average: LoadAverage,
    pub process_count: usize,
    pub disks: Vec<DiskStat>,
    pub network_interfaces: Vec<NetInterface>,
}

impl SysInfo {
    pub fn collect() -> Result<Self> {
        Ok(SysInfo {
            hostname: Self::read_hostname()?,
            kernel_version: Self::read_kernel_version()?,
            cpu: Self::read_cpu_info()?,
            memory: Self::read_memory_info()?,
            uptime_seconds: Self::read_uptime().unwrap_or(0.0),
            load_average: Self::read_load_average().unwrap_or(LoadAverage {
                one_min: 0.0,
                five_min: 0.0,
                fifteen_min: 0.0,
                running_tasks: 0,
                total_tasks: 0,
            }),
            process_count: Self::count_processes().unwrap_or(0),
            disks: Self::read_disk_stats().unwrap_or_default(),
            network_interfaces: Self::read_net_interfaces().unwrap_or_default(),
        })
    }

    fn read_hostname() -> Result<String> {
        Ok(read_proc("/proc/sys/kernel/hostname")?.trim().to_string())
    }

    fn read_kernel_version() -> Result<String> {
        Ok(read_proc("/proc/version")?.trim().to_string())
    }

    fn read_cpu_info() -> Result<CpuInfo> {
        let content = read_proc("/proc/cpuinfo")?;
        let mut model = String::from("unknown");
        let mut cores: usize = 0;

        for line in content.lines() {
            if line.starts_with("model name") {
                if let Some(val) = line.split(':').nth(1) {
                    model = val.trim().to_string();
                }
            }
            if line.starts_with("processor") {
                cores += 1;
            }
        }

        Ok(CpuInfo { model, cores })
    }

    fn read_memory_info() -> Result<MemoryInfo> {
        let content = read_proc("/proc/meminfo")?;
        let mut map = HashMap::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let key = parts[0].trim_end_matches(':');
                if let Ok(val) = parts[1].parse::<u64>() {
                    map.insert(key.to_string(), val);
                }
            }
        }

        let total = *map.get("MemTotal").unwrap_or(&0);
        let free = *map.get("MemFree").unwrap_or(&0);
        let available = *map.get("MemAvailable").unwrap_or(&free);
        let buffers = *map.get("Buffers").unwrap_or(&0);
        let cached = *map.get("Cached").unwrap_or(&0);
        let used = total.saturating_sub(free + buffers + cached);
        let usage_pct = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        Ok(MemoryInfo {
            total_kb: total,
            available_kb: available,
            free_kb: free,
            buffers_kb: buffers,
            cached_kb: cached,
            used_kb: used,
            usage_percent: usage_pct,
        })
    }

    fn read_uptime() -> Result<f64> {
        let content = read_proc("/proc/uptime")?;
        content
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SysInfoError::Parse {
                field: "uptime".into(),
                detail: "could not parse first field".into(),
            })
    }

    fn read_load_average() -> Result<LoadAverage> {
        let content = read_proc("/proc/loadavg")?;
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SysInfoError::Parse {
                field: "loadavg".into(),
                detail: format!("expected 4+ fields, got {}", parts.len()),
            });
        }

        let tasks: Vec<&str> = parts[3].split('/').collect();
        let (running, total) = if tasks.len() == 2 {
            (
                tasks[0].parse().unwrap_or(0),
                tasks[1].parse().unwrap_or(0),
            )
        } else {
            (0, 0)
        };

        Ok(LoadAverage {
            one_min: parts[0].parse().unwrap_or(0.0),
            five_min: parts[1].parse().unwrap_or(0.0),
            fifteen_min: parts[2].parse().unwrap_or(0.0),
            running_tasks: running,
            total_tasks: total,
        })
    }

    fn count_processes() -> Result<usize> {
        let content = read_proc("/proc/stat")?;
        let count = content
            .lines()
            .filter(|l| l.starts_with("processes"))
            .filter_map(|l| l.split_whitespace().nth(1))
            .filter_map(|v| v.parse::<usize>().ok())
            .next()
            .unwrap_or(0);
        Ok(count)
    }

    fn read_disk_stats() -> Result<Vec<DiskStat>> {
        let content = read_proc("/proc/diskstats")?;
        let mut disks = Vec::new();

        for line in content.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 14 {
                let device = parts[2].to_string();
                // Skip partition entries (e.g., sda1) — only show whole disks
                if device.chars().last().map_or(false, |c| c.is_ascii_digit())
                    && device.len() > 3
                {
                    continue;
                }
                let reads = parts[3].parse().unwrap_or(0);
                let read_sec = parts[5].parse().unwrap_or(0);
                let writes = parts[7].parse().unwrap_or(0);
                let write_sec = parts[9].parse().unwrap_or(0);
                if reads > 0 || writes > 0 {
                    disks.push(DiskStat {
                        device,
                        reads_completed: reads,
                        writes_completed: writes,
                        read_sectors: read_sec,
                        write_sectors: write_sec,
                    });
                }
            }
        }

        Ok(disks)
    }

    fn read_net_interfaces() -> Result<Vec<NetInterface>> {
        let content = read_proc("/proc/net/dev")?;
        let mut interfaces = Vec::new();

        for line in content.lines().skip(2) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 11 {
                let name = parts[0].trim_end_matches(':').to_string();
                interfaces.push(NetInterface {
                    name,
                    rx_bytes: parts[1].parse().unwrap_or(0),
                    rx_packets: parts[2].parse().unwrap_or(0),
                    rx_errors: parts[3].parse().unwrap_or(0),
                    tx_bytes: parts[9].parse().unwrap_or(0),
                    tx_packets: parts[10].parse().unwrap_or(0),
                    tx_errors: parts[11].parse().unwrap_or(0),
                });
            }
        }

        Ok(interfaces)
    }
}

/// Format bytes into human-readable units
pub fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    for unit in UNITS {
        if size < 1024.0 {
            return format!("{size:.1} {unit}");
        }
        size /= 1024.0;
    }
    format!("{size:.1} PB")
}

/// Format seconds into human-readable uptime
pub fn format_uptime(seconds: f64) -> String {
    let secs = seconds as u64;
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {mins}m")
    } else if hours > 0 {
        format!("{hours}h {mins}m")
    } else {
        format!("{mins}m {secs}s", secs = secs % 60)
    }
}

/// Format KB into human-readable units
pub fn format_kb(kb: u64) -> String {
    format_bytes(kb * 1024)
}
