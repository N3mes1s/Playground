//! # Daemon Orchestrator
//!
//! The main event loop that ties everything together:
//! - Starts the HTTP gateway
//! - Launches channel listeners
//! - Runs the heartbeat engine
//! - Executes cron jobs
//! - Routes messages through the agent
//!
//! In the unikernel, this IS the kernel's main loop — `kernel_main` calls
//! `daemon::run()` which never returns.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use crate::agent::Agent;
use crate::channels::{self, Channel, ChannelConfig};
use crate::providers;
use crate::tools;
use crate::config;

/// Run the daemon — this is the unikernel's main loop.
pub fn run() -> ! {
    let cfg = config::get();

    // Create the LLM provider
    let provider_config = providers::ProviderConfig {
        provider_name: cfg.provider.clone(),
        api_key: cfg.api_key.clone(),
        model: cfg.model.clone(),
        temperature: cfg.temperature,
        max_tokens: cfg.max_tokens,
        api_base_url: None,
        timeout_ms: 120_000,
    };
    let provider = providers::create(provider_config);

    // Create the tool registry
    let tool_registry = tools::create_default_registry();
    let tool_specs = tool_registry.specs();

    // Build the system prompt
    let skills = crate::skills::load_all();
    let system_prompt = channels::build_system_prompt(
        &tool_specs,
        &skills,
        &cfg.identity,
    );

    // Create the agent
    let mut agent = Agent::new(provider, tool_registry, system_prompt);

    // Create and start channels
    let mut active_channels: Vec<Box<dyn Channel>> = Vec::new();

    for channel_name in &cfg.channels {
        let channel_config = ChannelConfig {
            channel_type: channel_name.clone(),
            enabled: true,
            token: String::new(), // Would come from config
            allowed_users: Vec::new(),
            extra: Vec::new(),
        };

        let mut channel = channels::create(channel_config);
        match channel.start() {
            Ok(()) => {
                crate::kprintln!("[daemon] started channel: {}", channel.name());
                active_channels.push(channel);
            }
            Err(e) => {
                crate::kprintln!("[daemon] failed to start {}: {}", channel_name, e);
            }
        }
    }

    // Start the heartbeat engine
    crate::heartbeat::start();

    // Start the cron scheduler
    crate::cron::start();

    // Start the gateway
    crate::gateway::start(cfg.gateway_port);

    crate::kprintln!("[daemon] all services started, entering main loop");
    crate::kprintln!("[daemon] provider: {} ({})", cfg.provider, cfg.model);
    crate::kprintln!("[daemon] channels: {:?}", cfg.channels);
    crate::kprintln!("[daemon] memory entries: {}", crate::memory::global().lock().count());

    let mut tick_count: u64 = 0;

    // ── Main event loop ────────────────────────────────────────────────
    loop {
        tick_count += 1;

        // Poll all channels for new messages
        for channel in active_channels.iter_mut() {
            let messages = channel.poll_messages();
            for msg in messages {
                // Process through the agent
                let response = agent.process_message(&msg);

                // Send response back through the channel
                if let Err(e) = channel.send_message(&msg.sender, &response) {
                    crate::kprintln!("[daemon] send error on {}: {}", channel.name(), e);
                }
            }
        }

        // Run scheduler tick (cooperative tasks)
        crate::kernel::sched::tick();

        // Heartbeat check (every ~10000 ticks)
        if tick_count % 10000 == 0 {
            crate::heartbeat::tick();
        }

        // Cron check (every ~100000 ticks)
        if tick_count % 100000 == 0 {
            crate::cron::tick();
        }

        // Health status (every ~1000000 ticks)
        if tick_count % 1000000 == 0 {
            let heap = crate::kernel::mm::heap_stats();
            let mem_count = crate::memory::global().lock().count();
            crate::kprintln!(
                "[health] heap: {}/{} bytes | memories: {} | tasks: {} | history: {}",
                heap.used_bytes,
                heap.total_bytes,
                mem_count,
                crate::kernel::sched::task_count(),
                agent.history_len()
            );
        }

        // Yield to prevent busy-spinning from consuming 100% CPU
        // In a real unikernel, we'd use HLT here until an interrupt fires
        core::hint::spin_loop();
    }
}
