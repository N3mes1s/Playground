//! # Daemon Orchestrator
//!
//! The main event loop that ties everything together:
//! - Starts the HTTP gateway
//! - Launches channel listeners
//! - Runs the heartbeat engine
//! - Executes cron jobs
//! - Routes messages through the agent
//! - Manages tunnel connectivity
//! - Runs memory hygiene cycles
//! - Syncs skills from remote repos
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

    // ── Run startup diagnostics ──────────────────────────────────────────
    crate::kprintln!("[daemon] running startup diagnostics...");
    let report = crate::doctor::run_diagnostics();
    crate::kernel::console::puts(&report.to_string());

    // ── Initialize AIEOS identity ────────────────────────────────────────
    let aieos_identity = match crate::identity::AieosIdentity::load() {
        Some(id) => {
            crate::kprintln!("[daemon] loaded AIEOS v{} identity: {}", id.version, id.agent_name);
            id
        }
        None => {
            let id = crate::identity::AieosIdentity::from_config(&cfg.identity);
            id.save();
            crate::kprintln!("[daemon] created default AIEOS identity: {}", id.agent_name);
            id
        }
    };

    // ── Create the LLM provider (resilient with fallbacks) ───────────────
    let provider: Box<dyn providers::Provider> = {
        let provider_config = providers::ProviderConfig {
            provider_name: cfg.provider.clone(),
            api_key: cfg.api_key.clone(),
            model: cfg.model.clone(),
            temperature: cfg.temperature,
            max_tokens: cfg.max_tokens,
            api_base_url: None,
            timeout_ms: 120_000,
        };
        let retry_config = crate::providers::resilient::RetryConfig::default();
        Box::new(crate::providers::resilient::create_resilient(
            provider_config,
            Vec::new(), // Fallbacks can be added via config
            retry_config,
        ))
    };

    // ── Set up embedding provider for vector search ──────────────────────
    {
        let api_key = cfg.env_vars.get("OPENAI_API_KEY")
            .or_else(|| Some(&cfg.api_key))
            .cloned()
            .unwrap_or_default();
        let model = cfg.env_vars.get("EMBEDDING_MODEL")
            .cloned()
            .unwrap_or_else(|| String::from("text-embedding-3-small"));
        let custom_url = cfg.env_vars.get("EMBEDDING_URL").map(|s| s.as_str());
        let embedding_provider = crate::memory::embeddings::create_provider(
            &api_key, &model, custom_url,
        );
        let mem = crate::memory::global();
        let mut mem = mem.lock();
        mem.set_embedding_provider(embedding_provider);
    }

    // ── Create the tool registry ─────────────────────────────────────────
    let tool_registry = tools::create_default_registry();
    let tool_specs = tool_registry.specs();

    // ── Build the system prompt (with AIEOS identity) ────────────────────
    let skills = crate::skills::load_all();
    let mut system_prompt = channels::build_system_prompt(
        &tool_specs,
        &skills,
        &cfg.identity,
    );

    // Append AIEOS identity directives to system prompt
    let identity_prompt = aieos_identity.to_system_prompt();
    if !identity_prompt.is_empty() {
        system_prompt.push_str("\n\n");
        system_prompt.push_str(&identity_prompt);
    }

    // ── Create the agent ─────────────────────────────────────────────────
    let mut agent = Agent::new(provider, tool_registry, system_prompt);

    // ── Initialize webhook message queue ───────────────────────────────
    channels::init_webhook_queue();

    // ── Create and start channels ────────────────────────────────────────
    let mut active_channels: Vec<Box<dyn Channel>> = Vec::new();

    for channel_name in &cfg.channels {
        let channel_config = ChannelConfig {
            channel_type: channel_name.clone(),
            enabled: true,
            token: String::new(),
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

    // ── Start tunnel ─────────────────────────────────────────────────────
    let tunnel_type = cfg.env_vars.get("TUNNEL_TYPE")
        .cloned()
        .unwrap_or_default();
    if !tunnel_type.is_empty() {
        let tunnel_token = cfg.env_vars.get("TUNNEL_TOKEN")
            .cloned()
            .unwrap_or_default();
        let tunnel_extra = cfg.env_vars.get("TUNNEL_EXTRA")
            .map(|s| s.as_str());
        let mut tunnel = crate::tunnel::create(&tunnel_type, &tunnel_token, tunnel_extra);
        match tunnel.start(cfg.gateway_port) {
            Ok(url) => crate::kprintln!("[daemon] tunnel started: {}", url),
            Err(e) => crate::kprintln!("[daemon] tunnel error: {}", e),
        }
    }

    // ── Start the heartbeat engine ───────────────────────────────────────
    crate::heartbeat::start();

    // ── Start the cron scheduler ─────────────────────────────────────────
    crate::cron::start();

    // ── Start the gateway ────────────────────────────────────────────────
    crate::gateway::start(cfg.gateway_port);

    // ── Git sync skills on startup ───────────────────────────────────────
    let mut git_sync_config = crate::skills::git_sync::GitSyncConfig::default();
    if let Some(repo) = cfg.env_vars.get("SKILLS_REPO") {
        // Parse owner/name from repo string
        let parts: Vec<&str> = repo.split('/').collect();
        if parts.len() >= 2 {
            git_sync_config.repo_owner = String::from(parts[0]);
            git_sync_config.repo_name = String::from(parts[1]);
        }
    }

    crate::kprintln!("[daemon] all services started, entering main loop");
    crate::kprintln!("[daemon] provider: {} ({}) [resilient]", cfg.provider, cfg.model);
    crate::kprintln!("[daemon] channels: {:?}", cfg.channels);
    crate::kprintln!("[daemon] memory entries: {}", crate::memory::global().lock().entry_count());
    crate::kprintln!("[daemon] integrations: {}", crate::integrations::summary());

    let mut tick_count: u64 = 0;

    // ── Main event loop ────────────────────────────────────────────────
    loop {
        tick_count += 1;

        // Poll network for incoming frames (ARP, TCP, etc.)
        crate::net::poll();

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

        // Drain webhook messages (from gateway HTTP endpoints and heartbeat)
        let webhook_msgs = channels::drain_webhook_messages();
        for msg in webhook_msgs {
            let response = agent.process_message(&msg);
            crate::kprintln!(
                "[daemon] webhook response for {}: {} bytes",
                msg.channel, response.len()
            );
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

        // Memory hygiene (every ~5000000 ticks, roughly every few minutes)
        if tick_count % 5000000 == 0 {
            let mem = crate::memory::global();
            let mut mem = mem.lock();
            let summary = mem.run_hygiene();
            if summary.archived + summary.pruned + summary.deduplicated > 0 {
                crate::kprintln!(
                    "[hygiene] archived={} pruned={} deduped={} evicted={}",
                    summary.archived, summary.pruned,
                    summary.deduplicated, summary.evicted
                );
            }
        }

        // Skills git sync check (every ~10000000 ticks)
        if tick_count % 10000000 == 0 {
            if crate::skills::git_sync::should_sync(&git_sync_config) {
                let result = crate::skills::git_sync::sync(&git_sync_config);
                if result.skills_added > 0 || result.skills_updated > 0 {
                    crate::kprintln!(
                        "[daemon] skills sync: +{} updated={}",
                        result.skills_added, result.skills_updated
                    );
                }
                git_sync_config.last_sync = crate::kernel::rdtsc();
            }
        }

        // Health status (every ~1000000 ticks)
        if tick_count % 1000000 == 0 {
            let heap = crate::kernel::mm::heap_stats();
            let mem_count = crate::memory::global().lock().entry_count();
            let metrics = crate::observability::snapshot();
            crate::kprintln!(
                "[health] heap: {}/{} | memories: {} | tasks: {} | history: {} | reqs: {} | errors: {}",
                crate::util::format_bytes(heap.used_bytes),
                crate::util::format_bytes(heap.total_bytes),
                mem_count,
                crate::kernel::sched::task_count(),
                agent.history_len(),
                metrics.total_requests,
                metrics.total_errors
            );
        }

        // Yield to prevent busy-spinning from consuming 100% CPU
        // In a real unikernel, we'd use HLT here until an interrupt fires
        core::hint::spin_loop();
    }
}
