// SPDX-License-Identifier: GPL-2.0
//
// CO-RE eBPF probe for the depot-ci nested-virt experiment.
//
// Attaches to the sys_enter_execve tracepoint, reads two
// CO-RE-relocatable fields from struct task_struct (pid +
// real_parent->pid + comm[]), and emits one record per event onto a
// ringbuf. The ringbuf is drained by the userspace loader (loader.c)
// running as PID 1 inside the FC guest.
//
// Reading task_struct fields by name (BPF_CORE_READ) is what makes
// this a real CO-RE test — libbpf rewrites the field offsets at load
// time using the kernel's own BTF. A probe that only used helpers
// like bpf_get_current_pid_tgid() would pass on any kernel without
// proving CO-RE worked.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct probe_event {
	__u32 pid;
	__u32 ppid;
	char  comm[16];
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 14);  // 16 KiB ringbuf
} events SEC(".maps");

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *ctx)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task();

	struct probe_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;

	e->pid  = BPF_CORE_READ(t, pid);
	e->ppid = BPF_CORE_READ(t, real_parent, pid);
	BPF_CORE_READ_STR_INTO(&e->comm, t, comm);

	bpf_ringbuf_submit(e, 0);
	return 0;
}
