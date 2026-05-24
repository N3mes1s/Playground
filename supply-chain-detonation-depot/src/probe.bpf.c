// SPDX-License-Identifier: GPL-2.0
//
// Supply-chain detonation BPF probe.
//
// Attaches to a handful of syscalls that matter for install-time
// behaviour fingerprinting:
//
//   sys_enter_execve   — every binary spawned during the install
//   sys_enter_connect  — every network destination contacted
//                        (port + IP; userspace can reverse-DNS)
//
// Stage 1 keeps the surface small. Stage 2 adds openat-writes
// outside the install root and the suspicious-syscall family
// (ptrace, chmod /usr/*, etc.).
//
// Events are emitted on a single 1 MiB ringbuf; userspace
// deduplicates + aggregates before printing the JSON fingerprint.
//
// CO-RE: read task_struct fields via BPF_CORE_READ so the same
// .bpf.o boots against any kernel BTF (PR #19 verified this across
// 5.15 / 6.1 / 6.6 / 6.12).

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define EV_EXECVE  1
#define EV_CONNECT 2

#define AF_INET   2
#define AF_INET6 10

struct event {
	__u32 type;
	__u32 pid;
	__u32 ppid;
	char  comm[16];
	union {
		struct {
			char filename[128];
		} execve;
		struct {
			__u32 family;
			__u32 port;       // host byte order
			__u8  addr_v4[4];
			__u8  addr_v6[16];
		} conn;
	};
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);  // 1 MiB
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int on_execve(struct trace_event_raw_sys_enter *ctx)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EV_EXECVE;
	e->pid  = BPF_CORE_READ(t, pid);
	e->ppid = BPF_CORE_READ(t, real_parent, pid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	void *filename_ptr = (void *)ctx->args[0];
	bpf_probe_read_user_str(&e->execve.filename,
	                        sizeof(e->execve.filename),
	                        filename_ptr);

	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/syscalls/sys_enter_connect")
int on_connect(struct trace_event_raw_sys_enter *ctx)
{
	void *uservaddr = (void *)ctx->args[1];
	int addrlen = (int)ctx->args[2];

	__u16 family = 0;
	if (bpf_probe_read_user(&family, sizeof(family), uservaddr) != 0)
		return 0;

	if (family != AF_INET && family != AF_INET6)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	__builtin_memset(e, 0, sizeof(*e));
	e->type = EV_CONNECT;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();
	e->pid = BPF_CORE_READ(t, pid);
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->conn.family = family;

	if (family == AF_INET && addrlen >= (int)sizeof(struct sockaddr_in)) {
		struct sockaddr_in sa;
		if (bpf_probe_read_user(&sa, sizeof(sa), uservaddr) == 0) {
			e->conn.port = bpf_ntohs(sa.sin_port);
			__builtin_memcpy(e->conn.addr_v4, &sa.sin_addr.s_addr, 4);
		}
	} else if (family == AF_INET6 && addrlen >= (int)sizeof(struct sockaddr_in6)) {
		struct sockaddr_in6 sa;
		if (bpf_probe_read_user(&sa, sizeof(sa), uservaddr) == 0) {
			e->conn.port = bpf_ntohs(sa.sin6_port);
			__builtin_memcpy(e->conn.addr_v6,
			                 &sa.sin6_addr.in6_u.u6_addr8,
			                 16);
		}
	} else {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	bpf_ringbuf_submit(e, 0);
	return 0;
}
