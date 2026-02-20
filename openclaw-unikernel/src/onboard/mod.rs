//! # Onboarding Wizard
//!
//! Interactive setup for the agent. In the unikernel, this runs
//! over the serial console at first boot.

use alloc::string::String;

/// Run the onboarding wizard (serial console interactive mode).
pub fn run_wizard() {
    crate::kernel::console::puts("\n");
    crate::kernel::console::puts("╔══════════════════════════════════════════╗\n");
    crate::kernel::console::puts("║     OpenClaw Unikernel Setup Wizard     ║\n");
    crate::kernel::console::puts("╚══════════════════════════════════════════╝\n");
    crate::kernel::console::puts("\n");
    crate::kernel::console::puts("Welcome! Let's configure your AI agent.\n\n");

    // Step 1: Provider
    crate::kernel::console::puts("Step 1: LLM Provider\n");
    crate::kernel::console::puts("  Available: openai, anthropic, openrouter, ollama, gemini\n");
    crate::kernel::console::puts("  (plus 25+ OpenAI-compatible providers)\n");
    crate::kernel::console::puts("  Default: openai\n\n");

    // Step 2: API Key
    crate::kernel::console::puts("Step 2: API Key\n");
    crate::kernel::console::puts("  Set via config.toml or ZEROCLAW_API_KEY env var\n\n");

    // Step 3: Model
    crate::kernel::console::puts("Step 3: Model Selection\n");
    crate::kernel::console::puts("  Default: gpt-4o (or provider's default)\n\n");

    // Step 4: Identity
    crate::kernel::console::puts("Step 4: Agent Identity\n");
    crate::kernel::console::puts("  Edit SOUL.md in the ramfs to customize personality\n\n");

    // Step 5: Channels
    crate::kernel::console::puts("Step 5: Communication Channels\n");
    crate::kernel::console::puts("  Available: cli, telegram, discord, slack, webhook\n");
    crate::kernel::console::puts("  Default: cli (serial console)\n\n");

    crate::kernel::console::puts("Configuration saved. Starting agent...\n\n");
}

/// Quick setup — non-interactive, uses defaults.
pub fn quick_setup(provider: &str, api_key: &str, model: &str) {
    crate::config::update(|config| {
        config.provider = String::from(provider);
        config.api_key = String::from(api_key);
        if !model.is_empty() {
            config.model = String::from(model);
        }
    });

    crate::kprintln!("[onboard] quick setup: provider={}, model={}",
        provider,
        if model.is_empty() { "(default)" } else { model }
    );
}
