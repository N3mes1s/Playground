"""
chrome_sandbox.py - Python ctypes bindings for the Chrome sandbox harness.

Loads libchrome_sandbox_harness.so and exposes a Pythonic API to:
- Configure seccomp-BPF policies (STRICT/PERMISSIVE/TRACE_ALL)
- Execute commands inside Chrome's sandbox
- Capture stdout, stderr, and a full JSON syscall log
- Query kernel capabilities (seccomp-BPF, user namespaces)
"""

import ctypes
import ctypes.util
import json
import os
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Optional


# Locate the shared library
_LIB_SEARCH_PATHS = [
    Path(__file__).parent / "extracted" / "build" / "libchrome_sandbox_harness.so",
    Path(__file__).parent / "build" / "libchrome_sandbox_harness.so",
]

_lib = None
for _path in _LIB_SEARCH_PATHS:
    if _path.exists():
        _lib = ctypes.CDLL(str(_path))
        break

if _lib is None:
    raise RuntimeError(
        "Could not find libchrome_sandbox_harness.so. "
        "Build with: cd extracted/build && cmake .. && make chrome_sandbox_harness"
    )


# --- Enums ---

class PolicyLevel(IntEnum):
    STRICT = 0       # Block dangerous syscalls, broker FS access
    PERMISSIVE = 1   # Allow most, block truly dangerous
    TRACE_ALL = 2    # Allow all but trace every syscall


# --- ctypes struct ---

class _SandboxResult(ctypes.Structure):
    _fields_ = [
        ("exit_code", ctypes.c_int),
        ("stdout_buf", ctypes.c_char_p),
        ("stdout_len", ctypes.c_size_t),
        ("stderr_buf", ctypes.c_char_p),
        ("stderr_len", ctypes.c_size_t),
        ("syscall_log", ctypes.c_char_p),
        ("syscall_log_len", ctypes.c_size_t),
        ("num_syscalls_total", ctypes.c_int),
        ("num_syscalls_blocked", ctypes.c_int),
        ("duration_seconds", ctypes.c_double),
    ]


# --- Declare function signatures ---

_lib.sandbox_init.argtypes = []
_lib.sandbox_init.restype = ctypes.c_int

_lib.sandbox_shutdown.argtypes = []
_lib.sandbox_shutdown.restype = None

_lib.sandbox_set_policy.argtypes = [ctypes.c_int]
_lib.sandbox_set_policy.restype = None

_lib.sandbox_set_allowed_paths.argtypes = [ctypes.c_char_p]
_lib.sandbox_set_allowed_paths.restype = ctypes.c_int

_lib.sandbox_exec.argtypes = [ctypes.POINTER(ctypes.c_char_p)]
_lib.sandbox_exec.restype = _SandboxResult

_lib.sandbox_exec_shell.argtypes = [ctypes.c_char_p]
_lib.sandbox_exec_shell.restype = _SandboxResult

_lib.sandbox_result_free.argtypes = [ctypes.POINTER(_SandboxResult)]
_lib.sandbox_result_free.restype = None

_lib.sandbox_has_seccomp_bpf.argtypes = []
_lib.sandbox_has_seccomp_bpf.restype = ctypes.c_int

_lib.sandbox_has_user_namespaces.argtypes = []
_lib.sandbox_has_user_namespaces.restype = ctypes.c_int

_lib.sandbox_kernel_version.argtypes = []
_lib.sandbox_kernel_version.restype = ctypes.c_char_p

_lib.sandbox_set_namespaces_enabled.argtypes = [ctypes.c_int]
_lib.sandbox_set_namespaces_enabled.restype = None

_lib.sandbox_get_namespaces_enabled.argtypes = []
_lib.sandbox_get_namespaces_enabled.restype = ctypes.c_int


# --- Pythonic wrapper ---

@dataclass
class SandboxResult:
    """Result of executing a command inside the Chrome sandbox."""
    exit_code: int
    stdout: str
    stderr: str
    syscall_log: list  # List of dicts: {nr, name, risk, args}
    num_syscalls_total: int
    num_syscalls_blocked: int
    duration_seconds: float


class ChromeSandbox:
    """
    Python interface to Chrome's seccomp-BPF sandbox.

    Uses the actual extracted Chromium sandbox C++ code compiled into
    libchrome_sandbox_harness.so. The sandbox enforces syscall policies
    via BPF programs and traces all syscall activity.

    Usage:
        sandbox = ChromeSandbox()
        result = sandbox.run("echo hello")
        print(result.stdout)        # "hello\n"
        print(result.syscall_log)   # [{nr: 1, name: "write", risk: "LOW", ...}, ...]
    """

    def __init__(self, policy: PolicyLevel = PolicyLevel.TRACE_ALL,
                 namespaces: bool = True):
        rc = _lib.sandbox_init()
        if rc != 0:
            raise RuntimeError("Failed to initialize Chrome sandbox")
        self._policy = policy
        _lib.sandbox_set_policy(int(policy))
        _lib.sandbox_set_namespaces_enabled(1 if namespaces else 0)

    def set_policy(self, policy: PolicyLevel) -> None:
        """Change the seccomp-BPF policy level."""
        self._policy = policy
        _lib.sandbox_set_policy(int(policy))

    def set_allowed_paths(self, paths: list[str]) -> None:
        """Set paths the broker is allowed to open on behalf of sandboxed process."""
        joined = ":".join(paths)
        _lib.sandbox_set_allowed_paths(joined.encode("utf-8"))

    def run(self, command: str) -> SandboxResult:
        """Execute a shell command inside the Chrome sandbox."""
        raw = _lib.sandbox_exec_shell(command.encode("utf-8"))
        result = self._convert_result(raw)
        _lib.sandbox_result_free(ctypes.byref(raw))
        return result

    def run_argv(self, argv: list[str]) -> SandboxResult:
        """Execute a command with explicit argv inside the Chrome sandbox."""
        # Build null-terminated char*[] array
        c_argv = (ctypes.c_char_p * (len(argv) + 1))()
        for i, arg in enumerate(argv):
            c_argv[i] = arg.encode("utf-8")
        c_argv[len(argv)] = None

        raw = _lib.sandbox_exec(c_argv)
        result = self._convert_result(raw)
        _lib.sandbox_result_free(ctypes.byref(raw))
        return result

    @staticmethod
    def has_seccomp_bpf() -> bool:
        """Check if seccomp-BPF is available on this kernel."""
        return _lib.sandbox_has_seccomp_bpf() == 1

    @staticmethod
    def has_user_namespaces() -> bool:
        """Check if user namespaces are available."""
        return _lib.sandbox_has_user_namespaces() == 1

    def set_namespaces_enabled(self, enabled: bool) -> None:
        """Enable or disable namespace isolation layers."""
        _lib.sandbox_set_namespaces_enabled(1 if enabled else 0)

    @staticmethod
    def kernel_version() -> str:
        """Get the kernel version string."""
        v = _lib.sandbox_kernel_version()
        return v.decode("utf-8") if v else "unknown"

    def close(self) -> None:
        """Shutdown the sandbox."""
        _lib.sandbox_shutdown()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @staticmethod
    def _convert_result(raw: _SandboxResult) -> SandboxResult:
        stdout = raw.stdout_buf.decode("utf-8", errors="replace") if raw.stdout_buf else ""
        stderr = raw.stderr_buf.decode("utf-8", errors="replace") if raw.stderr_buf else ""
        try:
            syscall_log = json.loads(
                raw.syscall_log.decode("utf-8") if raw.syscall_log else "[]"
            )
        except json.JSONDecodeError:
            syscall_log = []

        return SandboxResult(
            exit_code=raw.exit_code,
            stdout=stdout,
            stderr=stderr,
            syscall_log=syscall_log,
            num_syscalls_total=raw.num_syscalls_total,
            num_syscalls_blocked=raw.num_syscalls_blocked,
            duration_seconds=raw.duration_seconds,
        )


# Quick self-test when run directly
if __name__ == "__main__":
    print(f"Kernel: {ChromeSandbox.kernel_version()}")
    print(f"seccomp-BPF available: {ChromeSandbox.has_seccomp_bpf()}")
    print(f"User namespaces available: {ChromeSandbox.has_user_namespaces()}")

    with ChromeSandbox(PolicyLevel.TRACE_ALL) as sb:
        print("\n--- Running 'echo hello world' in Chrome sandbox ---")
        r = sb.run("echo hello world")
        print(f"Exit code: {r.exit_code}")
        print(f"Stdout: {r.stdout!r}")
        print(f"Stderr: {r.stderr!r}")
        print(f"Syscalls traced: {r.num_syscalls_total}")
        print(f"Duration: {r.duration_seconds:.4f}s")
        if r.syscall_log:
            print(f"\nFirst 10 syscalls:")
            for sc in r.syscall_log[:10]:
                nr = sc.get("nr", "?")
                name = sc.get("name", f"#{nr}")
                risk = sc.get("risk", "?")
                print(f"  {name} (risk: {risk})")
