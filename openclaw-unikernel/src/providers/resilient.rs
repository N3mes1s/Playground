//! # Resilient Provider
//!
//! Wraps a primary provider with fallback chains and retry logic.
//! If the primary fails, it tries fallback providers in order.
//! Each attempt uses exponential backoff.
//!
//! Circuit breaker pattern tracks provider health:
//! - Closed: Normal operation, requests pass through
//! - Open: Provider is unhealthy, requests are blocked
//! - HalfOpen: Probing recovery, allow one test request

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use core::cell::UnsafeCell;
use super::{Provider, Message, ToolSpec, CompletionResponse, ProviderConfig};

/// Retry configuration.
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retries per provider
    pub max_retries: u32,
    /// Initial backoff in milliseconds
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds
    pub max_backoff_ms: u64,
    /// Backoff multiplier (e.g., 2.0 for exponential)
    pub backoff_multiplier: f32,
}

impl Default for RetryConfig {
    fn default() -> Self {
        RetryConfig {
            max_retries: 3,
            initial_backoff_ms: 1000,
            max_backoff_ms: 30_000,
            backoff_multiplier: 2.0,
        }
    }
}

/// Circuit breaker states for provider health tracking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircuitState {
    Closed,       // Normal operation — requests pass through
    Open,         // Tripped — requests are blocked
    HalfOpen,     // Testing — allow one request to probe recovery
}

/// Per-provider health tracker.
struct ProviderHealth {
    state: CircuitState,
    consecutive_failures: u32,
    last_failure_tsc: u64,
    total_successes: u64,
    total_failures: u64,
    /// Failure threshold before opening circuit
    failure_threshold: u32,
    /// TSC ticks to wait before half-open probe (~30s at 2GHz)
    recovery_timeout_ticks: u64,
}

impl ProviderHealth {
    fn new() -> Self {
        ProviderHealth {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            last_failure_tsc: 0,
            total_successes: 0,
            total_failures: 0,
            failure_threshold: 3,
            recovery_timeout_ticks: 60_000_000_000, // ~30s at 2GHz
        }
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.total_successes += 1;
        self.state = CircuitState::Closed;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        self.total_failures += 1;
        self.last_failure_tsc = crate::kernel::rdtsc();

        if self.consecutive_failures >= self.failure_threshold {
            self.state = CircuitState::Open;
            crate::kprintln!(
                "[circuit] opened after {} consecutive failures",
                self.consecutive_failures
            );
        }
    }

    fn should_attempt(&mut self) -> bool {
        match self.state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let now = crate::kernel::rdtsc();
                if now.saturating_sub(self.last_failure_tsc) >= self.recovery_timeout_ticks {
                    self.state = CircuitState::HalfOpen;
                    crate::kprintln!("[circuit] transitioning to half-open for probe");
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }
}

/// Interior-mutable health wrapper.
/// Safe in the unikernel's cooperative single-threaded scheduler.
struct HealthCell(UnsafeCell<ProviderHealth>);

// Safety: The unikernel uses cooperative scheduling with no preemption.
// Only one task runs at a time, so there are no data races.
unsafe impl Send for HealthCell {}
unsafe impl Sync for HealthCell {}

impl HealthCell {
    fn new() -> Self {
        HealthCell(UnsafeCell::new(ProviderHealth::new()))
    }

    fn get(&self) -> &mut ProviderHealth {
        // Safety: Single-threaded cooperative scheduler — no concurrent access
        unsafe { &mut *self.0.get() }
    }
}

/// A resilient provider that wraps a primary + fallback chain.
pub struct ResilientProvider {
    primary: Box<dyn Provider>,
    fallbacks: Vec<Box<dyn Provider>>,
    primary_health: HealthCell,
    fallback_health: Vec<HealthCell>,
    retry_config: RetryConfig,
}

impl ResilientProvider {
    pub fn new(primary: Box<dyn Provider>) -> Self {
        ResilientProvider {
            primary,
            fallbacks: Vec::new(),
            primary_health: HealthCell::new(),
            fallback_health: Vec::new(),
            retry_config: RetryConfig::default(),
        }
    }

    /// Add a fallback provider to the chain.
    pub fn with_fallback(mut self, provider: Box<dyn Provider>) -> Self {
        self.fallbacks.push(provider);
        self.fallback_health.push(HealthCell::new());
        self
    }

    /// Set the retry configuration.
    pub fn with_retry_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    /// Attempt a completion with retries against a single provider.
    fn try_provider(
        &self,
        provider: &dyn Provider,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        let mut last_error = String::from("no attempts made");
        let mut backoff_ms = self.retry_config.initial_backoff_ms;

        for attempt in 0..=self.retry_config.max_retries {
            if attempt > 0 {
                crate::kprintln!(
                    "[resilient] retry {}/{} for {} (backoff {}ms)",
                    attempt, self.retry_config.max_retries, provider.name(), backoff_ms
                );
                crate::kernel::syscall::sys_sleep_ms(backoff_ms);
                backoff_ms = core::cmp::min(
                    (backoff_ms as f32 * self.retry_config.backoff_multiplier) as u64,
                    self.retry_config.max_backoff_ms,
                );
            }

            match provider.complete(messages, tools) {
                Ok(response) => return Ok(response),
                Err(e) => {
                    last_error = e;
                    // Don't retry on 4xx errors (client errors)
                    if last_error.contains("400") || last_error.contains("401")
                        || last_error.contains("403") || last_error.contains("422")
                    {
                        return Err(last_error);
                    }
                }
            }
        }

        Err(last_error)
    }
}

impl Provider for ResilientProvider {
    fn name(&self) -> &str {
        "resilient"
    }

    fn complete(
        &self,
        messages: &[Message],
        tools: &[ToolSpec],
    ) -> Result<CompletionResponse, String> {
        // Try primary provider if circuit breaker allows it
        let primary_health = self.primary_health.get();
        if primary_health.should_attempt() {
            match self.try_provider(&*self.primary, messages, tools) {
                Ok(response) => {
                    primary_health.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    primary_health.record_failure();
                    crate::kprintln!(
                        "[resilient] primary '{}' failed (failures: {}): {}",
                        self.primary.name(),
                        primary_health.consecutive_failures,
                        e
                    );
                }
            }
        } else {
            crate::kprintln!(
                "[resilient] primary '{}' circuit is open, skipping",
                self.primary.name()
            );
        }

        // Try fallback providers in order
        for (i, fallback) in self.fallbacks.iter().enumerate() {
            if i >= self.fallback_health.len() {
                continue;
            }

            let health = self.fallback_health[i].get();
            if !health.should_attempt() {
                crate::kprintln!(
                    "[resilient] fallback '{}' circuit is open, skipping",
                    fallback.name()
                );
                continue;
            }

            crate::kprintln!(
                "[resilient] trying fallback '{}' ({}/{})",
                fallback.name(), i + 1, self.fallbacks.len()
            );

            match self.try_provider(&**fallback, messages, tools) {
                Ok(response) => {
                    health.record_success();
                    return Ok(response);
                }
                Err(e) => {
                    health.record_failure();
                    crate::kprintln!(
                        "[resilient] fallback '{}' failed (failures: {}): {}",
                        fallback.name(),
                        health.consecutive_failures,
                        e
                    );
                }
            }
        }

        Err(format!(
            "all providers failed (primary + {} fallbacks exhausted)",
            self.fallbacks.len()
        ))
    }

    fn health_check(&self) -> Result<(), String> {
        // Check primary
        if let Ok(()) = self.primary.health_check() {
            return Ok(());
        }
        // Check fallbacks
        for fallback in &self.fallbacks {
            if let Ok(()) = fallback.health_check() {
                return Ok(());
            }
        }
        Err(String::from("no healthy providers available"))
    }
}

/// Create a resilient provider from a config with fallback chain.
pub fn create_resilient(
    primary_config: ProviderConfig,
    fallback_configs: Vec<ProviderConfig>,
    retry_config: RetryConfig,
) -> ResilientProvider {
    let primary = super::create(primary_config);
    let mut resilient = ResilientProvider::new(primary).with_retry_config(retry_config);

    for config in fallback_configs {
        let fallback = super::create(config);
        resilient = resilient.with_fallback(fallback);
    }

    resilient
}
