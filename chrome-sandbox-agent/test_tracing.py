"""Test that all policy modes trace syscalls and detect blocked calls."""
from chrome_sandbox import ChromeSandbox, PolicyLevel

print("=== TRACE_ALL mode ===")
sb = ChromeSandbox(PolicyLevel.TRACE_ALL)
r = sb.run("echo hello")
print("Syscalls: {}  Blocked: {}".format(r.num_syscalls_total, r.num_syscalls_blocked))
print("stdout:", repr(r.stdout))
assert r.num_syscalls_total > 0, "TRACE_ALL should trace syscalls"

print("\n=== STRICT mode ===")
sb.set_policy(PolicyLevel.STRICT)
r = sb.run("echo hello from strict")
print("Syscalls: {}  Blocked: {}".format(r.num_syscalls_total, r.num_syscalls_blocked))
print("stdout:", repr(r.stdout))
assert r.num_syscalls_total > 0, "STRICT should also trace syscalls now"

# Test that STRICT blocks network sockets
print("\n=== STRICT: network socket (should be blocked) ===")
r = sb.run('python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)"')
print("Exit: {}  Syscalls: {}  Blocked: {}".format(r.exit_code, r.num_syscalls_total, r.num_syscalls_blocked))
blocked_syscalls = [s for s in r.syscall_log if s.get("blocked")]
print("Blocked syscalls:")
for s in blocked_syscalls[:10]:
    print("  {} (risk: {})".format(s.get("name", "?"), s.get("risk", "?")))
assert r.num_syscalls_blocked > 0, "STRICT should block network socket"

# Test path extraction
print("\n=== TRACE_ALL: path extraction ===")
sb.set_policy(PolicyLevel.TRACE_ALL)
r = sb.run("cat /etc/hostname 2>/dev/null; echo done")
paths_seen = [s.get("path", "") for s in r.syscall_log if s.get("path")]
print("File paths accessed ({} total):".format(len(paths_seen)))
for p in paths_seen[:15]:
    print("  {}".format(p))

# Test PERMISSIVE mode
print("\n=== PERMISSIVE mode ===")
sb.set_policy(PolicyLevel.PERMISSIVE)
r = sb.run("echo hello permissive")
print("Syscalls: {}  Blocked: {}".format(r.num_syscalls_total, r.num_syscalls_blocked))
assert r.num_syscalls_total > 0, "PERMISSIVE should trace syscalls"

sb.close()
print("\nAll tests passed!")
