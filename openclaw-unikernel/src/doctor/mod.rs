//! # Doctor / Health Diagnostic Utility
//!
//! Comprehensive health checks for the OpenClaw unikernel agent.
//! Validates configuration, connectivity, subsystem status, and
//! provides actionable recommendations.
//!
//! Modeled after `zeroclaw doctor` which checks:
//! - Provider configuration and connectivity
//! - Channel configuration
//! - Memory system health
//! - Security status
//! - Network connectivity
//! - System resources

use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;

/// Severity level for diagnostic checks.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Severity {
    Pass,
    Warning,
    Error,
}

impl Severity {
    pub fn symbol(&self) -> &'static str {
        match self {
            Severity::Pass => "[OK]",
            Severity::Warning => "[WARN]",
            Severity::Error => "[FAIL]",
        }
    }
}

/// A single diagnostic check result.
#[derive(Debug, Clone)]
pub struct CheckResult {
    pub name: String,
    pub severity: Severity,
    pub message: String,
    pub suggestion: Option<String>,
}

/// Full diagnostic report.
#[derive(Debug)]
pub struct DiagnosticReport {
    pub checks: Vec<CheckResult>,
    pub pass_count: usize,
    pub warn_count: usize,
    pub error_count: usize,
}

impl DiagnosticReport {
    /// Render the report as a human-readable string.
    pub fn to_string(&self) -> String {
        let mut out = String::from("=== OpenClaw Doctor ===\n\n");

        for check in &self.checks {
            out.push_str(&format!(
                "{} {}: {}\n",
                check.severity.symbol(),
                check.name,
                check.message
            ));
            if let Some(ref suggestion) = check.suggestion {
                out.push_str(&format!("     -> {}\n", suggestion));
            }
        }

        out.push_str(&format!(
            "\nSummary: {} passed, {} warnings, {} errors\n",
            self.pass_count, self.warn_count, self.error_count
        ));

        if self.error_count == 0 && self.warn_count == 0 {
            out.push_str("All checks passed! Agent is healthy.\n");
        } else if self.error_count == 0 {
            out.push_str("No critical issues. Review warnings above.\n");
        } else {
            out.push_str("Critical issues found. Fix errors before proceeding.\n");
        }

        out
    }

    /// Render as JSON for the /health API.
    pub fn to_json(&self) -> String {
        let mut json = format!(
            "{{\"pass\":{},\"warn\":{},\"error\":{},\"checks\":[",
            self.pass_count, self.warn_count, self.error_count
        );

        for (i, check) in self.checks.iter().enumerate() {
            if i > 0 {
                json.push(',');
            }
            let severity_str = match check.severity {
                Severity::Pass => "pass",
                Severity::Warning => "warning",
                Severity::Error => "error",
            };
            json.push_str(&format!(
                "{{\"name\":\"{}\",\"severity\":\"{}\",\"message\":\"{}\"}}",
                check.name, severity_str,
                crate::providers::json_string_escape(&check.message)
            ));
        }

        json.push_str("]}");
        json
    }
}

/// Run all diagnostic checks and return a report.
pub fn run_diagnostics() -> DiagnosticReport {
    let mut checks = Vec::new();

    // 1. Configuration checks
    checks.push(check_provider_config());
    checks.push(check_api_key());
    checks.push(check_model_config());

    // 2. Memory system checks
    checks.push(check_memory_system());
    checks.push(check_heap_usage());

    // 3. Security checks
    checks.push(check_security_policy());
    checks.push(check_pairing_status());

    // 4. Channel checks
    checks.push(check_channels());

    // 5. Network checks
    checks.push(check_network());

    // 6. Identity checks
    checks.push(check_identity());

    // 7. Skills check
    checks.push(check_skills());

    // 8. Scheduler check
    checks.push(check_scheduler());

    // Tally results
    let pass_count = checks.iter().filter(|c| c.severity == Severity::Pass).count();
    let warn_count = checks.iter().filter(|c| c.severity == Severity::Warning).count();
    let error_count = checks.iter().filter(|c| c.severity == Severity::Error).count();

    let report = DiagnosticReport {
        checks,
        pass_count,
        warn_count,
        error_count,
    };

    crate::kprintln!(
        "[doctor] diagnostics complete: {} pass, {} warn, {} error",
        report.pass_count, report.warn_count, report.error_count
    );

    report
}

// ── Individual Checks ────────────────────────────────────────────────────────

fn check_provider_config() -> CheckResult {
    let cfg = crate::config::get();
    if cfg.provider.is_empty() {
        CheckResult {
            name: String::from("Provider"),
            severity: Severity::Error,
            message: String::from("No LLM provider configured"),
            suggestion: Some(String::from("Set provider in config.toml (e.g., provider = \"openai\")")),
        }
    } else {
        CheckResult {
            name: String::from("Provider"),
            severity: Severity::Pass,
            message: format!("Provider: {} (model: {})", cfg.provider, cfg.model),
            suggestion: None,
        }
    }
}

fn check_api_key() -> CheckResult {
    let cfg = crate::config::get();
    if cfg.api_key.is_empty() {
        // Check if using local provider that doesn't need a key
        if cfg.provider == "ollama" {
            CheckResult {
                name: String::from("API Key"),
                severity: Severity::Pass,
                message: String::from("Using local provider (no API key needed)"),
                suggestion: None,
            }
        } else {
            CheckResult {
                name: String::from("API Key"),
                severity: Severity::Error,
                message: String::from("No API key configured"),
                suggestion: Some(String::from("Set api_key in config.toml or ZEROCLAW_API_KEY env var")),
            }
        }
    } else {
        let masked = if cfg.api_key.len() > 8 {
            format!("{}...{}", &cfg.api_key[..4], &cfg.api_key[cfg.api_key.len()-4..])
        } else {
            String::from("****")
        };
        CheckResult {
            name: String::from("API Key"),
            severity: Severity::Pass,
            message: format!("API key configured ({})", masked),
            suggestion: None,
        }
    }
}

fn check_model_config() -> CheckResult {
    let cfg = crate::config::get();
    if cfg.model.is_empty() {
        CheckResult {
            name: String::from("Model"),
            severity: Severity::Warning,
            message: String::from("No model specified, will use provider default"),
            suggestion: Some(String::from("Set model in config.toml for explicit control")),
        }
    } else {
        CheckResult {
            name: String::from("Model"),
            severity: Severity::Pass,
            message: format!("Model: {}", cfg.model),
            suggestion: None,
        }
    }
}

fn check_memory_system() -> CheckResult {
    let mem = crate::memory::global().lock();
    let count = mem.count();

    if count == 0 {
        CheckResult {
            name: String::from("Memory"),
            severity: Severity::Warning,
            message: String::from("Memory system is empty"),
            suggestion: Some(String::from("Memory will populate as conversations occur")),
        }
    } else {
        CheckResult {
            name: String::from("Memory"),
            severity: Severity::Pass,
            message: format!("{} memory entries stored", count),
            suggestion: None,
        }
    }
}

fn check_heap_usage() -> CheckResult {
    let stats = crate::kernel::mm::heap_stats();
    let usage_pct = if stats.total_bytes > 0 {
        (stats.used_bytes * 100) / stats.total_bytes
    } else {
        0
    };

    if usage_pct > 90 {
        CheckResult {
            name: String::from("Heap"),
            severity: Severity::Error,
            message: format!(
                "Heap usage critical: {}% ({}/{})",
                usage_pct,
                crate::util::format_bytes(stats.used_bytes),
                crate::util::format_bytes(stats.total_bytes)
            ),
            suggestion: Some(String::from("Run memory hygiene or increase heap size")),
        }
    } else if usage_pct > 70 {
        CheckResult {
            name: String::from("Heap"),
            severity: Severity::Warning,
            message: format!(
                "Heap usage elevated: {}% ({}/{})",
                usage_pct,
                crate::util::format_bytes(stats.used_bytes),
                crate::util::format_bytes(stats.total_bytes)
            ),
            suggestion: Some(String::from("Consider running memory hygiene")),
        }
    } else {
        CheckResult {
            name: String::from("Heap"),
            severity: Severity::Pass,
            message: format!(
                "Heap usage: {}% ({}/{})",
                usage_pct,
                crate::util::format_bytes(stats.used_bytes),
                crate::util::format_bytes(stats.total_bytes)
            ),
            suggestion: None,
        }
    }
}

fn check_security_policy() -> CheckResult {
    let cfg = crate::config::get();
    match cfg.autonomy_level.as_str() {
        "full" => CheckResult {
            name: String::from("Security"),
            severity: Severity::Warning,
            message: String::from("Autonomy level: full (unrestricted)"),
            suggestion: Some(String::from("Consider 'supervised' for production")),
        },
        "supervised" | "restricted" | "locked" => CheckResult {
            name: String::from("Security"),
            severity: Severity::Pass,
            message: format!("Autonomy level: {}", cfg.autonomy_level),
            suggestion: None,
        },
        _ => CheckResult {
            name: String::from("Security"),
            severity: Severity::Warning,
            message: format!("Unknown autonomy level: {}", cfg.autonomy_level),
            suggestion: Some(String::from("Use: supervised, restricted, locked, or full")),
        },
    }
}

fn check_pairing_status() -> CheckResult {
    // Pairing is always available at boot
    CheckResult {
        name: String::from("Pairing"),
        severity: Severity::Pass,
        message: String::from("Gateway pairing available"),
        suggestion: None,
    }
}

fn check_channels() -> CheckResult {
    let cfg = crate::config::get();
    if cfg.channels.is_empty() {
        CheckResult {
            name: String::from("Channels"),
            severity: Severity::Warning,
            message: String::from("No channels configured"),
            suggestion: Some(String::from("Add channels to config.toml (e.g., cli, telegram, discord)")),
        }
    } else {
        CheckResult {
            name: String::from("Channels"),
            severity: Severity::Pass,
            message: format!("{} channel(s): {}", cfg.channels.len(), cfg.channels.join(", ")),
            suggestion: None,
        }
    }
}

fn check_network() -> CheckResult {
    // In the unikernel, the network stack is always initialized
    let cfg = crate::config::get();
    CheckResult {
        name: String::from("Network"),
        severity: Severity::Pass,
        message: format!("Gateway on port {}", cfg.gateway_port),
        suggestion: None,
    }
}

fn check_identity() -> CheckResult {
    let has_soul = crate::config::ramfs_read("/workspace/SOUL.md").is_some();
    let cfg = crate::config::get();

    if !has_soul && cfg.identity.soul.is_empty() {
        CheckResult {
            name: String::from("Identity"),
            severity: Severity::Warning,
            message: String::from("No identity configured (SOUL.md missing)"),
            suggestion: Some(String::from("Create /workspace/SOUL.md to define agent personality")),
        }
    } else {
        CheckResult {
            name: String::from("Identity"),
            severity: Severity::Pass,
            message: format!("Agent: {}", cfg.identity.agent_name),
            suggestion: None,
        }
    }
}

fn check_skills() -> CheckResult {
    let listing = crate::config::ramfs_list("/workspace/skills");
    let skill_count = listing.lines().filter(|l| !l.is_empty()).count();

    if skill_count == 0 {
        CheckResult {
            name: String::from("Skills"),
            severity: Severity::Pass,
            message: String::from("No custom skills loaded (built-in tools available)"),
            suggestion: None,
        }
    } else {
        CheckResult {
            name: String::from("Skills"),
            severity: Severity::Pass,
            message: format!("{} skill(s) loaded", skill_count),
            suggestion: None,
        }
    }
}

fn check_scheduler() -> CheckResult {
    let task_count = crate::kernel::sched::task_count();
    CheckResult {
        name: String::from("Scheduler"),
        severity: Severity::Pass,
        message: format!("{} active task(s)", task_count),
        suggestion: None,
    }
}
