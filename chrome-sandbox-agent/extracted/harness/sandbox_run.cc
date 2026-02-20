// sandbox-run: Portable standalone CLI for Chrome's seccomp-BPF sandbox.
//
// Single binary. No Python, no shared libraries, no runtime dependencies.
// Statically links all of Chrome's sandbox code.
//
// Usage:
//   sandbox-run <command> [args...]
//   sandbox-run --network claude
//   sandbox-run --workspace /path bash
//   sandbox-run --readonly /opt/node22:/root/.cargo --network claude -p "hello"
//
// All 8 Chrome security layers active:
//   1. User NS  2. PID NS  3. IPC NS  4. Network NS  5. Mount NS + chroot
//   6. Cap drop  7. seccomp-BPF  8. ptrace filesystem broker

#include "harness/sandbox_harness.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void print_usage(const char* prog) {
    fprintf(stderr,
        "Usage: %s [options] <command> [args...]\n"
        "\n"
        "Run any command inside Chrome's seccomp-BPF sandbox.\n"
        "\n"
        "Options:\n"
        "  --workspace DIR, -w DIR   Host dir to mount read-write (default: CWD)\n"
        "  --no-workspace            Don't mount any workspace\n"
        "  --network                 Enable network access (default: blocked)\n"
        "  --readonly PATHS          Colon-separated read-only mount paths\n"
        "  --allowed PATHS           Colon-separated read-write mount paths\n"
        "  --policy LEVEL            STRICT (default), PERMISSIVE, or TRACE_ALL\n"
        "  --verbose, -v             Print config before launching\n"
        "  --help, -h                Show this help\n"
        "\n"
        "Environment variables:\n"
        "  SANDBOX_WORKSPACE         Workspace directory\n"
        "  SANDBOX_NETWORK=1         Enable network\n"
        "  SANDBOX_READONLY_PATHS    Colon-separated read-only paths\n"
        "  SANDBOX_ALLOWED_PATHS     Colon-separated read-write paths\n"
        "  SANDBOX_POLICY            Policy level\n"
        "\n"
        "Examples:\n"
        "  %s bash                              Interactive shell\n"
        "  %s --network claude                  Claude Code with network\n"
        "  %s --readonly /opt/node22 --network claude -p \"hello\"\n"
        "  %s --workspace ./project python3 app.py\n"
        "  %s --no-workspace bash               Ephemeral /tmp only\n"
        "\n"
        "Security: 8 isolation layers (user/PID/IPC/net NS, chroot, caps,\n"
        "          seccomp-BPF, ptrace broker). Sandboxed process can only\n"
        "          access workspace + system dirs. All else blocked.\n",
        prog, prog, prog, prog, prog, prog);
}

int main(int argc, char* argv[]) {
    const char* workspace = nullptr;
    bool no_workspace = false;
    bool network = false;
    bool verbose = false;
    const char* readonly_paths = nullptr;
    const char* allowed_paths = nullptr;
    const char* policy_str = nullptr;
    int cmd_start = -1;

    // Check env vars first (CLI flags override)
    const char* env_val;
    if ((env_val = getenv("SANDBOX_NETWORK")) != nullptr) {
        network = (strcmp(env_val, "1") == 0 || strcmp(env_val, "true") == 0);
    }
    if ((env_val = getenv("SANDBOX_WORKSPACE")) != nullptr) {
        workspace = env_val;
    }
    if ((env_val = getenv("SANDBOX_READONLY_PATHS")) != nullptr) {
        readonly_paths = env_val;
    }
    if ((env_val = getenv("SANDBOX_ALLOWED_PATHS")) != nullptr) {
        allowed_paths = env_val;
    }
    if ((env_val = getenv("SANDBOX_POLICY")) != nullptr) {
        policy_str = env_val;
    }
    if (getenv("SANDBOX_VERBOSE") != nullptr) {
        verbose = true;
    }

    // Parse CLI flags
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "--verbose") == 0 || strcmp(argv[i], "-v") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--network") == 0) {
            network = true;
        } else if (strcmp(argv[i], "--no-workspace") == 0) {
            no_workspace = true;
        } else if ((strcmp(argv[i], "--workspace") == 0 || strcmp(argv[i], "-w") == 0) && i + 1 < argc) {
            workspace = argv[++i];
        } else if (strcmp(argv[i], "--readonly") == 0 && i + 1 < argc) {
            readonly_paths = argv[++i];
        } else if (strcmp(argv[i], "--allowed") == 0 && i + 1 < argc) {
            allowed_paths = argv[++i];
        } else if (strcmp(argv[i], "--policy") == 0 && i + 1 < argc) {
            policy_str = argv[++i];
        } else if (strcmp(argv[i], "--") == 0) {
            cmd_start = i + 1;
            break;
        } else if (argv[i][0] == '-' && argv[i][1] != '\0') {
            fprintf(stderr, "sandbox-run: unknown option: %s\n", argv[i]);
            fprintf(stderr, "Try: %s --help\n", argv[0]);
            return 1;
        } else {
            // First non-option arg is the command
            cmd_start = i;
            break;
        }
    }

    if (cmd_start < 0 || cmd_start >= argc) {
        fprintf(stderr, "sandbox-run: no command specified.\n");
        fprintf(stderr, "Usage: %s [options] <command> [args...]\n", argv[0]);
        fprintf(stderr, "Try: %s --help\n", argv[0]);
        return 1;
    }

    // Default workspace = CWD
    char cwd_buf[4096];
    if (!no_workspace && workspace == nullptr) {
        if (getcwd(cwd_buf, sizeof(cwd_buf)) != nullptr) {
            workspace = cwd_buf;
        }
    }
    if (no_workspace) {
        workspace = nullptr;
    }

    // Build allowed paths: workspace + any extra --allowed paths
    // Format: colon-separated string
    char all_allowed[8192] = {0};
    int off = 0;
    if (workspace != nullptr) {
        off += snprintf(all_allowed + off, sizeof(all_allowed) - off, "%s", workspace);
    }
    if (allowed_paths != nullptr && allowed_paths[0] != '\0') {
        if (off > 0) all_allowed[off++] = ':';
        snprintf(all_allowed + off, sizeof(all_allowed) - off, "%s", allowed_paths);
    }

    // Parse policy
    SandboxPolicyLevel policy = SANDBOX_POLICY_STRICT;
    if (policy_str != nullptr) {
        if (strcmp(policy_str, "PERMISSIVE") == 0) {
            policy = SANDBOX_POLICY_PERMISSIVE;
        } else if (strcmp(policy_str, "TRACE_ALL") == 0) {
            policy = SANDBOX_POLICY_TRACE_ALL;
        } else if (strcmp(policy_str, "STRICT") != 0) {
            fprintf(stderr, "sandbox-run: unknown policy: %s (use STRICT, PERMISSIVE, or TRACE_ALL)\n", policy_str);
            return 1;
        }
    }

    // Verbose output
    if (verbose) {
        fprintf(stderr, "\033[2msandbox-run: Chrome seccomp-BPF sandbox\n");
        fprintf(stderr, "  Command:  ");
        for (int i = cmd_start; i < argc; i++) {
            fprintf(stderr, " %s", argv[i]);
        }
        fprintf(stderr, "\n");
        fprintf(stderr, "  Workspace: %s\n", workspace ? workspace : "(none - ephemeral /tmp only)");
        fprintf(stderr, "  Network:   %s\n", network ? "enabled" : "disabled");
        fprintf(stderr, "  Policy:    %s\n", policy_str ? policy_str : "STRICT");
        if (readonly_paths) fprintf(stderr, "  Read-only: %s\n", readonly_paths);
        if (allowed_paths) fprintf(stderr, "  Allowed:   %s\n", allowed_paths);
        fprintf(stderr, "  seccomp:   %s\n", sandbox_has_seccomp_bpf() ? "active" : "NOT available");
        fprintf(stderr, "  Kernel:    %s\n", sandbox_kernel_version());
        fprintf(stderr, "\033[0m");
    }

    // Configure sandbox (must be before sandbox_init)
    sandbox_set_policy(policy);
    sandbox_set_exec_policy(SANDBOX_EXEC_BROKERED);
    sandbox_set_network_enabled(network ? 1 : 0);

    if (all_allowed[0] != '\0') {
        sandbox_set_allowed_paths(all_allowed);
    }
    if (readonly_paths != nullptr && readonly_paths[0] != '\0') {
        sandbox_set_readonly_paths(readonly_paths);
    }

    // Initialize sandbox (creates zygote with namespace isolation)
    int rc = sandbox_init();
    if (rc != 0) {
        fprintf(stderr, "sandbox-run: failed to initialize sandbox (rc=%d)\n", rc);
        fprintf(stderr, "Ensure you have: unprivileged user namespaces, seccomp-BPF\n");
        return 1;
    }

    // Build argv for the sandboxed command
    const char** cmd_argv = (const char**)malloc(sizeof(char*) * (argc - cmd_start + 1));
    if (!cmd_argv) {
        fprintf(stderr, "sandbox-run: out of memory\n");
        sandbox_shutdown();
        return 1;
    }
    for (int i = cmd_start; i < argc; i++) {
        cmd_argv[i - cmd_start] = argv[i];
    }
    cmd_argv[argc - cmd_start] = nullptr;

    // Run the command interactively inside the sandbox
    int exit_code = sandbox_exec_interactive(cmd_argv);

    free(cmd_argv);
    sandbox_shutdown();
    return exit_code;
}
