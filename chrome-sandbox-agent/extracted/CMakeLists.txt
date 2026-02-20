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
    sandbox/linux/services/credentials.cc
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
target_link_libraries(sandbox_services PUBLIC sandbox_seccomp_bpf cap)

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

# =============================================================================
# Test infrastructure: Chrome's test harness (unit_tests, bpf_tests, etc.)
# =============================================================================
find_package(GTest REQUIRED)

# Test support library (Chrome's test harness compiled against gtest)
add_library(sandbox_test_support STATIC
    sandbox/linux/tests/unit_tests.cc
    sandbox/linux/tests/test_utils.cc
    sandbox/linux/tests/sandbox_test_runner.cc
    sandbox/linux/tests/sandbox_test_runner_function_pointer.cc
    sandbox/linux/tests/scoped_temporary_file.cc
    sandbox/linux/seccomp-bpf/sandbox_bpf_test_runner.cc
)
target_include_directories(sandbox_test_support PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/testing/gtest/include
)
target_link_libraries(sandbox_test_support PUBLIC
    -Wl,--start-group
    sandbox_syscall_broker
    sandbox_services
    sandbox_seccomp_helpers
    sandbox_seccomp_bpf
    sandbox_bpf_dsl
    -Wl,--end-group
    pthread
    GTest::GTest
)

# =============================================================================
# Chrome sandbox unit tests (imported from Chromium source)
# =============================================================================
# These are Chrome's own unit tests for the sandbox components.
# They verify the BPF DSL, seccomp-BPF filter, syscall broker, etc.

# --- BPF DSL tests ---
add_executable(sandbox_bpf_dsl_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/bpf_dsl/syscall_set_unittest.cc
    sandbox/linux/bpf_dsl/cons_unittest.cc
    sandbox/linux/bpf_dsl/test_trap_registry.cc
    sandbox/linux/bpf_dsl/test_trap_registry_unittest.cc
)
target_link_libraries(sandbox_bpf_dsl_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- seccomp-BPF tests ---
add_executable(sandbox_seccomp_bpf_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/seccomp-bpf/trap_unittest.cc
    sandbox/linux/seccomp-bpf/bpf_tests_unittest.cc
    sandbox/linux/seccomp-bpf/sandbox_bpf_unittest.cc
    sandbox/linux/seccomp-bpf/syscall_unittest.cc
)
target_link_libraries(sandbox_seccomp_bpf_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- Syscall broker tests ---
add_executable(sandbox_broker_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/syscall_broker/broker_file_permission_unittest.cc
    sandbox/linux/syscall_broker/broker_simple_message_unittest.cc
    sandbox/linux/syscall_broker/broker_process_unittest.cc
    sandbox/linux/syscall_broker/remote_syscall_arg_handler_unittest.cc
)
target_link_libraries(sandbox_broker_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- BPF DSL integration tests (seccomp policy enforcement) ---
# The big integration test: bpf_dsl_seccomp_unittest.cc tests the full
# seccomp-BPF pipeline from policy creation through kernel enforcement.
add_executable(sandbox_integration_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/integration_tests/bpf_dsl_seccomp_unittest.cc
    sandbox/linux/integration_tests/seccomp_broker_process_unittest.cc
)
target_link_libraries(sandbox_integration_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- Seccomp-BPF helpers / baseline policy tests ---
add_executable(sandbox_helpers_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/seccomp-bpf-helpers/baseline_policy_unittest.cc
    sandbox/linux/seccomp-bpf-helpers/sigsys_handlers_unittest.cc
    sandbox/linux/seccomp-bpf-helpers/syscall_parameters_restrictions_unittest.cc
)
target_link_libraries(sandbox_helpers_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- Sandbox harness end-to-end integration test ---
# Tests the full stack: zygote, namespaces, seccomp, ptrace broker, exec policy
add_executable(sandbox_harness_test
    harness/sandbox_integration_test.cc
)
target_link_libraries(sandbox_harness_test PRIVATE
    chrome_sandbox_harness
)

# --- Claude Code in Chrome Sandbox test ---
# Tests Claude Code running inside the Chrome sandbox with real API calls
add_executable(claude_sandbox_test
    harness/claude_sandbox_test.c
)
target_link_libraries(claude_sandbox_test PRIVATE
    chrome_sandbox_harness
)

# --- Agent smoke test ---
# Tests agent-like workflows: file ops, pipelines, security boundaries
add_executable(agent_smoke_test
    harness/agent_smoke_test.c
)
target_link_libraries(agent_smoke_test PRIVATE
    chrome_sandbox_harness
)

# --- Python in Chrome Sandbox test ---
# Tests Python runtime inside the Chrome sandbox: interpreter, file I/O,
# JSON processing, subprocess, and Claude API calls via urllib
add_executable(python_sandbox_test
    harness/python_sandbox_test.c
)
target_link_libraries(python_sandbox_test PRIVATE
    chrome_sandbox_harness
)

# --- Services tests ---
add_executable(sandbox_services_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/services/proc_util_unittest.cc
    sandbox/linux/services/resource_limits_unittest.cc
    sandbox/linux/services/syscall_wrappers_unittest.cc
    sandbox/linux/services/scoped_process_unittest.cc
    sandbox/linux/services/yama_unittest.cc
    sandbox/linux/services/credentials_unittest.cc
    sandbox/linux/services/namespace_utils_unittest.cc
    sandbox/linux/services/thread_helpers_unittest.cc
)
target_link_libraries(sandbox_services_tests PRIVATE
    sandbox_test_support
    cap
    GTest::GTest
    GTest::Main
)

# --- SUID sandbox client library ---
add_library(sandbox_suid_client STATIC
    sandbox/linux/suid/client/setuid_sandbox_client.cc
    sandbox/linux/suid/client/setuid_sandbox_host.cc
)
target_link_libraries(sandbox_suid_client PUBLIC sandbox_services)

# --- SUID client tests ---
add_executable(sandbox_suid_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/suid/client/setuid_sandbox_client_unittest.cc
    sandbox/linux/suid/client/setuid_sandbox_host_unittest.cc
)
target_link_libraries(sandbox_suid_tests PRIVATE
    sandbox_suid_client
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- Test infrastructure tests ---
add_executable(sandbox_test_infra_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/tests/unit_tests_unittest.cc
    sandbox/linux/tests/scoped_temporary_file_unittest.cc
)
target_link_libraries(sandbox_test_infra_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)

# --- Namespace / Unix domain socket integration test ---
add_executable(sandbox_namespace_tests
    sandbox/linux/tests/test_main.cc
    sandbox/linux/integration_tests/namespace_unix_domain_socket_unittest.cc
)
target_link_libraries(sandbox_namespace_tests PRIVATE
    sandbox_test_support
    GTest::GTest
    GTest::Main
)
