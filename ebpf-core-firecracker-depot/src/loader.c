// SPDX-License-Identifier: GPL-2.0
//
// Userspace loader running as PID 1 inside a Firecracker guest. Loads
// /probe.bpf.o via libbpf (this is where CO-RE relocations resolve
// against the kernel's BTF), attaches it to sys_enter_execve, fires
// an execve to trigger the probe, captures one event off the ringbuf,
// prints a JSON verdict between BPF_RESULT_BEGIN/END markers, and
// reboots so Firecracker exits cleanly.
//
// Built static-musl + libbpf-static so the initrd has zero shared-lib
// dependencies. See infra/docker/ebpf-runner.Dockerfile.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/reboot.h>

#include <bpf/libbpf.h>

// Must match struct probe_event in probe.bpf.c
struct probe_event {
	uint32_t pid;
	uint32_t ppid;
	char     comm[16];
};

static int event_count;
static struct probe_event last_event;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	if (data_sz < sizeof(struct probe_event))
		return 0;
	memcpy(&last_event, data, sizeof(last_event));
	event_count++;
	return 0;
}

static int libbpf_log(enum libbpf_print_level level, const char *fmt, va_list args)
{
	// keep WARN/ERROR on stderr; suppress INFO to keep serial clean
	if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, fmt, args);
}

// Get a monotonic millisecond timestamp.
static long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// Print a JSON line wrapped in the BEGIN/END markers expected by the
// host-side parser, then halt.
__attribute__((noreturn))
static void emit_and_halt(const char *json)
{
	printf("BPF_RESULT_BEGIN\n");
	printf("%s\n", json);
	printf("BPF_RESULT_END\n");
	fflush(stdout);
	sync();
	// Give the serial console a moment to drain through Firecracker's
	// UART emulator before we yank power.
	sleep(1);
	reboot(LINUX_REBOOT_CMD_RESTART);
	for (;;) pause();
}

int main(int argc, char **argv)
{
	long long t0 = now_ms();

	// As PID 1 we have to mount our own /proc, /sys, /sys/fs/bpf.
	// Ignore failures (the bpf filesystem might already be mounted by
	// the kernel, /proc might be required for libbpf, etc).
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mount("proc",  "/proc", "proc",  0, NULL);
	mount("sysfs", "/sys",  "sysfs", 0, NULL);
	mkdir("/sys/fs/bpf", 0755);
	mount("bpf",   "/sys/fs/bpf", "bpf", 0, NULL);
	// tracefs is required so libbpf can attach to tracepoints by path
	mkdir("/sys/kernel/tracing", 0755);
	mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, NULL);

	libbpf_set_print(libbpf_log);

	char errbuf[256];
	const char *json_fmt;
	(void)json_fmt;

	struct bpf_object *obj = bpf_object__open_file("/probe.bpf.o", NULL);
	long err = libbpf_get_error(obj);
	if (!obj || err) {
		snprintf(errbuf, sizeof(errbuf),
			 "{\"verdict\":\"FAIL\",\"stage\":\"open\",\"err\":%ld,\"errno\":%d}",
			 err, errno);
		emit_and_halt(errbuf);
	}

	if (bpf_object__load(obj)) {
		snprintf(errbuf, sizeof(errbuf),
			 "{\"verdict\":\"FAIL\",\"stage\":\"load\",\"errno\":%d,"
			 "\"note\":\"CO-RE relocation likely failed; check libbpf stderr\"}",
			 errno);
		emit_and_halt(errbuf);
	}

	struct bpf_program *prog = bpf_object__next_program(obj, NULL);
	if (!prog) {
		emit_and_halt("{\"verdict\":\"FAIL\",\"stage\":\"find_prog\"}");
	}

	struct bpf_link *link = bpf_program__attach(prog);
	if (!link || libbpf_get_error(link)) {
		snprintf(errbuf, sizeof(errbuf),
			 "{\"verdict\":\"FAIL\",\"stage\":\"attach\",\"errno\":%d}", errno);
		emit_and_halt(errbuf);
	}

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		emit_and_halt("{\"verdict\":\"FAIL\",\"stage\":\"find_map\"}");
	}

	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map), handle_event, NULL, NULL);
	if (!rb || libbpf_get_error(rb)) {
		emit_and_halt("{\"verdict\":\"FAIL\",\"stage\":\"ringbuf_new\"}");
	}

	long long t_loaded = now_ms();

	// Trigger sys_enter_execve from a child so we don't replace ourselves.
	// We intentionally exec a path that doesn't exist — the tracepoint
	// fires on syscall ENTRY, before the lookup that would fail with
	// -ENOENT, so the probe still observes the event.
	pid_t pid = fork();
	if (pid == 0) {
		char *args[] = { (char *)"trigger", NULL };
		execve("/nonexistent-trigger-path", args, NULL);
		_exit(0);
	}
	int status;
	if (pid > 0)
		waitpid(pid, &status, 0);

	// Poll the ringbuf up to ~5s for our event.
	long long deadline = t_loaded + 5000;
	while (event_count == 0 && now_ms() < deadline) {
		ring_buffer__poll(rb, 100);
	}

	long long t_event = now_ms();

	char json[512];
	if (event_count > 0) {
		// Sanitize comm for JSON (cap at NUL, no control chars).
		char comm[17];
		memcpy(comm, last_event.comm, 16);
		comm[16] = '\0';
		for (int i = 0; comm[i]; i++)
			if (comm[i] < 0x20 || comm[i] > 0x7e) comm[i] = '?';

		snprintf(json, sizeof(json),
			 "{\"verdict\":\"OK\","
			 "\"events\":%d,"
			 "\"pid\":%u,"
			 "\"ppid\":%u,"
			 "\"comm\":\"%s\","
			 "\"core_relocs\":\"resolved\","
			 "\"boot_to_load_ms\":%lld,"
			 "\"load_to_event_ms\":%lld}",
			 event_count, last_event.pid, last_event.ppid, comm,
			 t_loaded - t0, t_event - t_loaded);
	} else {
		snprintf(json, sizeof(json),
			 "{\"verdict\":\"FAIL\","
			 "\"stage\":\"no_events\","
			 "\"timeout_ms\":5000,"
			 "\"boot_to_load_ms\":%lld}",
			 t_loaded - t0);
	}

	emit_and_halt(json);
	return 0;
}
