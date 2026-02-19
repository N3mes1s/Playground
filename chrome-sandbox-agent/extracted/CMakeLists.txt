cmake_minimum_required(VERSION 3.10)
project(ChromeSandboxStandalone LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# Include paths: shims first (so they override Chromium's base/ includes),
# then the extracted sandbox source, then Chromium-style includes.
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/base_shims       # base/ shims
    ${CMAKE_CURRENT_SOURCE_DIR}/build_config      # build/build_config.h
    ${CMAKE_CURRENT_SOURCE_DIR}                    # sandbox/ (for sandbox/linux/...)
)

# Compiler flags matching Chromium's build settings for sandbox code
add_compile_options(
    -Wall -Wextra -Wno-unused-parameter -Wno-missing-field-initializers
    -Wno-sign-compare -Wno-implicit-fallthrough
    -DCOMPONENT_BUILD=0
    # Linux-specific
    -DOS_LINUX=1
    -DOS_POSIX=1
)
# Force-include our sanitizer/MSAN stub header
add_compile_options(-include ${CMAKE_CURRENT_SOURCE_DIR}/base_shims/standalone_compat.h)

# =============================================================================
# Library: sandbox_system_headers (zero deps, kernel constants)
# =============================================================================
add_library(sandbox_system_headers INTERFACE)
target_include_directories(sandbox_system_headers INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# =============================================================================
# Library: sandbox_bpf_dsl (BPF DSL for writing seccomp policies)
# =============================================================================
file(GLOB BPF_DSL_SOURCES sandbox/linux/bpf_dsl/*.cc)
# Remove test files
list(FILTER BPF_DSL_SOURCES EXCLUDE REGEX ".*_test\\.cc$")
list(FILTER BPF_DSL_SOURCES EXCLUDE REGEX ".*_unittest\\.cc$")
list(FILTER BPF_DSL_SOURCES EXCLUDE REGEX ".*_fuzzer\\.cc$")
list(FILTER BPF_DSL_SOURCES EXCLUDE REGEX ".*test_trap_registry\\.cc$")

add_library(sandbox_bpf_dsl STATIC ${BPF_DSL_SOURCES})
target_link_libraries(sandbox_bpf_dsl PUBLIC sandbox_system_headers)

# =============================================================================
# Library: sandbox_seccomp_bpf (core seccomp-BPF sandbox)
# =============================================================================
set(SECCOMP_BPF_SOURCES
    sandbox/linux/seccomp-bpf/die.cc
    sandbox/linux/seccomp-bpf/sandbox_bpf.cc
    sandbox/linux/seccomp-bpf/syscall.cc
    sandbox/linux/seccomp-bpf/trap.cc
)

add_library(sandbox_seccomp_bpf STATIC ${SECCOMP_BPF_SOURCES})
target_link_libraries(sandbox_seccomp_bpf PUBLIC sandbox_bpf_dsl)

# =============================================================================
# Library: sandbox_seccomp_helpers (baseline policies, syscall sets)
# =============================================================================
set(SECCOMP_HELPERS_SOURCES
    sandbox/linux/seccomp-bpf-helpers/baseline_policy.cc
    sandbox/linux/seccomp-bpf-helpers/sigsys_handlers.cc
    sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions.cc
    sandbox/linux/seccomp-bpf-helpers/syscall_sets.cc
)

add_library(sandbox_seccomp_helpers STATIC ${SECCOMP_HELPERS_SOURCES})
target_link_libraries(sandbox_seccomp_helpers PUBLIC sandbox_seccomp_bpf)

# =============================================================================
# Library: sandbox_services (credentials, namespaces, syscall wrappers)
# =============================================================================
# Core services only (namespace_sandbox, libc_interceptor, thread_helpers
# require too many base/ deps and are not needed for the sandbox itself)
set(SANDBOX_SERVICES_SOURCES
    sandbox/linux/services/init_process_reaper.cc
    sandbox/linux/services/namespace_utils.cc
    sandbox/linux/services/proc_util.cc
    sandbox/linux/services/resource_limits.cc
    sandbox/linux/services/scoped_process.cc
    sandbox/linux/services/syscall_wrappers.cc
    sandbox/linux/services/yama.cc
    sandbox/linux/services/thread_helpers_stub.cc
)

add_library(sandbox_services STATIC ${SANDBOX_SERVICES_SOURCES})
target_link_libraries(sandbox_services PUBLIC sandbox_seccomp_bpf)

# =============================================================================
# Library: sandbox_syscall_broker (broker process for proxying syscalls)
# =============================================================================
set(SYSCALL_BROKER_SOURCES
    sandbox/linux/syscall_broker/broker_channel.cc
    sandbox/linux/syscall_broker/broker_client.cc
    sandbox/linux/syscall_broker/broker_command.cc
    sandbox/linux/syscall_broker/broker_file_permission.cc
    sandbox/linux/syscall_broker/broker_host.cc
    sandbox/linux/syscall_broker/broker_permission_list.cc
    sandbox/linux/syscall_broker/broker_process.cc
    sandbox/linux/syscall_broker/broker_sandbox_config.cc
    sandbox/linux/syscall_broker/broker_simple_message.cc
    sandbox/linux/syscall_broker/remote_syscall_arg_handler.cc
    sandbox/linux/syscall_broker/syscall_dispatcher.cc
)

add_library(sandbox_syscall_broker STATIC ${SYSCALL_BROKER_SOURCES})
target_link_libraries(sandbox_syscall_broker PUBLIC sandbox_services)

# =============================================================================
# Combined library: chrome_sandbox_all
# =============================================================================
add_library(chrome_sandbox_all INTERFACE)
target_link_libraries(chrome_sandbox_all INTERFACE
    sandbox_bpf_dsl
    sandbox_seccomp_bpf
    sandbox_seccomp_helpers
    sandbox_services
    sandbox_syscall_broker
    pthread
)

# =============================================================================
# Executable: chrome-sandbox (the setuid helper binary, pure C)
# =============================================================================
add_executable(chrome-sandbox
    sandbox/linux/suid/sandbox.c
    sandbox/linux/suid/process_util_linux.c
)
target_include_directories(chrome-sandbox PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
target_compile_definitions(chrome-sandbox PRIVATE
    -DSANDBOX_EXPORT=
)

# =============================================================================
# Shared library: libchrome_sandbox_harness.so (for Python ctypes bindings)
# =============================================================================
add_library(chrome_sandbox_harness SHARED
    harness/sandbox_harness.cc
)
# Use --whole-archive to pull all symbols from static libs into the .so
target_link_libraries(chrome_sandbox_harness PRIVATE
    -Wl,--whole-archive
    sandbox_syscall_broker
    sandbox_services
    sandbox_seccomp_helpers
    sandbox_seccomp_bpf
    sandbox_bpf_dsl
    -Wl,--no-whole-archive
    pthread
)
target_include_directories(chrome_sandbox_harness PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)
set_target_properties(chrome_sandbox_harness PROPERTIES
    OUTPUT_NAME "chrome_sandbox_harness"
)
