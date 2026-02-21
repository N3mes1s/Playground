# Investigation: xattrat Seccomp Bypass in Flatpak & Firejail

## Quick Context

Linux 6.13 (January 2025) added 4 new syscalls: `getxattrat` (463), `setxattrat` (464), `listxattrat` (465), `removexattrat` (466) on x86-64.

**Denylist-based sandboxes let them through by default.** This affects Flatpak and Firejail.

---

## Investigation Thread 1: Flatpak

### What to verify

1. **Confirm the filter is still a denylist:**
   ```
   # Clone and check the seccomp filter code
   git clone https://github.com/flatpak/flatpak
   grep -rn "seccomp\|SCMP_ACT\|sock_filter\|seccomp_rule" flatpak/common/flatpak-run.c
   ```
   Look for `seccomp_rule_add` calls with `SCMP_ACT_KILL` or `SCMP_ACT_ERRNO`.
   The DEFAULT action should be `SCMP_ACT_ALLOW` (denylist) — if it is, the bug exists.

2. **Test directly:**
   ```bash
   # Inside a Flatpak sandbox
   flatpak run --command=bash org.freedesktop.Platform
   # Then run a C program that calls syscall(463, ...) / syscall(464, ...)
   # If it returns -ENODATA or succeeds: CONFIRMED BYPASS
   # If it returns -EPERM or -ENOSYS: already fixed
   ```

3. **Check if they added xattrat to the blocklist:**
   ```
   git log --all --oneline flatpak/common/flatpak-run.c | head -20
   # Search for any mention of xattrat
   grep -rn "xattr\|463\|464\|465\|466" flatpak/common/flatpak-run.c
   ```

4. **Check the allowlist migration status:**
   - Issue #4349: https://github.com/flatpak/flatpak/issues/4349
   - Issue #4462 (CVE-2021-41133 follow-up)
   - Bubblewrap PR #459 (prerequisite for multi-program seccomp)
   - LWN article on Flatpak stagnation: https://lwn.net/Articles/1020571/

### Attack scenario (Flatpak)

A malicious Flatpak app can:
1. Call `getxattrat(AT_FDCWD, "/path/to/file", "security.selinux", ...)` to read SELinux labels
2. Call `setxattrat(AT_FDCWD, "/path/to/file", "security.capability", ...)` to SET file capabilities on files in its mount namespace
3. Call `listxattrat()` to enumerate all xattrs on any accessible file
4. Combined with the **audit gap** (kernels 6.13-6.18), these calls are invisible to audit

### Key files in Flatpak codebase
- `common/flatpak-run.c` — where seccomp filter is built
- `common/flatpak-run-private.h` — seccomp-related declarations
- Look for `setup_seccomp()` or `flatpak_run_setup_seccomp()`

### Prior art (same bug class)
- **CVE-2021-41133**: `clone3`, `open_tree`, `move_mount`, `fsopen`, `fsconfig`, `fsmount`, `fspick` bypassed Flatpak's denylist
- The fix was to add those specific syscalls to the blocklist — NOT to switch to an allowlist
- This means EVERY new kernel syscall creates the same vulnerability

---

## Investigation Thread 2: Firejail

### What to verify

1. **Confirm the default blocklist:**
   ```
   git clone https://github.com/netblue30/firejail
   # Check default seccomp profile
   cat firejail/src/firecfg/firejail.config
   grep -rn "syscall\|seccomp\|blacklist\|blocklist" firejail/src/fseccomp/
   ```
   Look in `src/fseccomp/seccomp.c` or `src/fseccomp/syscall.c` for the default blocked list.

2. **Check /usr/share/doc/firejail/syscalls.txt:**
   ```
   # On a system with firejail installed:
   cat /usr/share/doc/firejail/syscalls.txt | grep -i xattr
   ```
   If xattrat syscalls are NOT listed → bypass confirmed.

3. **Test directly:**
   ```bash
   # Inside a Firejail sandbox
   firejail bash
   # Run test program calling syscall(463, ...)
   ```

4. **Check the allowlist alternative:**
   ```
   # Firejail supports --seccomp.keep (allowlist mode)
   firejail --seccomp.keep=read,write,open,close,mmap,... bash
   # This would block xattrat by default, but it's not the default mode
   ```

### Key files in Firejail codebase
- `src/fseccomp/seccomp.c` — seccomp filter builder
- `src/fseccomp/syscall.c` — syscall name/number mapping
- `etc/firejail-default.profile` — default profile
- Look for `seccomp_load()` or `seccomp_default_drop()`

### Attack scenario (Firejail)

Same as Flatpak, plus:
- Firejail is often used to sandbox browsers, email clients, document viewers
- A compromised process in a Firejail sandbox can read/modify security xattrs
- Combined with audit gap: operations are completely invisible

---

## Investigation Thread 3: The Audit Gap

### Kernels affected: 6.13 through 6.18

1. **Verify the bug:**
   ```bash
   # On kernel 6.13+
   # Set up an audit watch rule:
   sudo auditctl -w /tmp/test_file -p rwa -k test_xattr

   # Write a test xattr the OLD way (should generate audit log):
   setfattr -n user.test -v "hello" /tmp/test_file
   ausearch -k test_xattr  # Should show the event

   # Now read the xattr the NEW way (should NOT generate audit log):
   # Use a C program that calls getxattrat(AT_FDCWD, "/tmp/test_file", "user.test", ...)
   ausearch -k test_xattr  # NO new event — audit bypassed!
   ```

2. **Check the fix status:**
   - Patch: http://www.mail-archive.com/audit@vger.kernel.org/msg01832.html
   - Author: Jeffrey Bencteux
   - Status: merged into audit/dev, queued for Linux v7.0
   - Check: `git log --oneline include/linux/audit_read.h` in kernel tree

3. **What's missing in the kernel:**
   ```c
   // In include/linux/audit_read.h, these lines are MISSING on 6.13-6.18:
   #ifdef __NR_getxattrat
   __NR_getxattrat,
   #endif
   #ifdef __NR_listxattrat
   __NR_listxattrat,
   #endif
   ```
   Without these, `audit_match_perm()` returns 0 for read-permission audit watches on getxattrat/listxattrat.

---

## Investigation Thread 4: Cross-Reference with Other Projects

### Already patched (for comparison)
- **Docker v28+**: Moby PR #50077 — added xattrat to allowlist
- **snapd**: template.go updated
- **systemd**: seccomp-util.c updated (`@file-system` group)
- **libseccomp v2.6.0**: includes xattrat definitions

### Useful for your investigation
```bash
# Check libseccomp version on your system
pkg-config --modversion libseccomp

# Check if your kernel has the syscalls
grep xattr /proc/kallsyms 2>/dev/null | grep "at$"

# Check kernel version
uname -r
# If >= 6.13: xattrat syscalls exist in kernel
# If < 6.13: they return ENOSYS regardless of seccomp

# Quick test program (compile with: gcc -o xattrat_test xattrat_test.c)
cat > /tmp/xattrat_test.c << 'CEOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>

struct xattr_args {
    uint64_t value;
    uint32_t size;
    uint32_t flags;
};

int main(void) {
    char buf[256];
    struct xattr_args args = {
        .value = (uint64_t)(uintptr_t)buf,
        .size = sizeof(buf),
        .flags = 0
    };

    long ret = syscall(463, -100, "/etc/hostname", "user.test", &args, 0);
    printf("getxattrat returned %ld, errno=%d (%s)\n",
           ret, errno, strerror(errno));

    if (errno == 38) printf("ENOSYS: kernel doesn't have xattrat (< 6.13)\n");
    else if (errno == 1) printf("EPERM: blocked by seccomp/ptrace\n");
    else if (errno == 13) printf("EACCES: blocked by broker/permissions\n");
    else if (errno == 61) printf("ENODATA: syscall EXECUTED, xattr doesn't exist\n");
    else if (ret >= 0) printf("SUCCESS: xattr read succeeded!\n");

    return 0;
}
CEOF
```

---

## Reproduction Steps Summary

### For Flatpak
```bash
# 1. Get a Flatpak sandbox
flatpak install flathub org.freedesktop.Platform//23.08
flatpak run --command=bash org.freedesktop.Platform//23.08

# 2. Compile the test (inside sandbox, or copy binary in)
gcc -static -o /tmp/xattrat_test /tmp/xattrat_test.c

# 3. Run inside Flatpak
# Expected on kernel >= 6.13: "ENODATA: syscall EXECUTED"
# This confirms the bypass — seccomp denylist didn't catch it
```

### For Firejail
```bash
# 1. Get a Firejail sandbox
firejail --noprofile bash

# 2. Run the test binary
/tmp/xattrat_test

# Expected on kernel >= 6.13: "ENODATA: syscall EXECUTED"
# This confirms the bypass
```

### For your (now-fixed) sandbox
```bash
# Run test_74 — should now show ALL PASS
sandbox-run --workspace tests/advanced -- ./test_74_xattrat_new

# Expected output:
# getxattrat() blocked — blocked (EACCES — broker denied)
# setxattrat() blocked — blocked (EPERM — ptrace/seccomp)
# etc.
```

---

## Responsible Disclosure Notes

- Flatpak: Consider filing via https://github.com/flatpak/flatpak/security/advisories (same pattern as CVE-2021-41133)
- Firejail: Consider filing at https://github.com/netblue30/firejail/issues
- The kernel audit bug was already reported and fixed (queued for v7.0)
- This is NOT a zero-day — it's a known consequence of denylist architecture
- The kernel docs explicitly recommend allowlists: https://docs.kernel.org/userspace-api/seccomp_filter.html
