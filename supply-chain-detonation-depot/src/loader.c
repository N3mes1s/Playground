// SPDX-License-Identifier: GPL-2.0
//
// Userspace loader / init for the supply-chain detonation experiment.
//
// Runs as PID 1 inside a Firecracker guest. Mounts essentials, attaches
// the BPF probe (probe.bpf.o), spawns `npm install <pkg>` into a tmpfs,
// pollss the ringbuf until the install exits, aggregates the events
// into a JSON fingerprint, emits it between DETONATION_BEGIN/END
// markers, and reboots so Firecracker exits exit_code=0.
//
// The package to detonate is read from /proc/cmdline. Kernel boot args
// can pass it after the standard "--" init-args separator:
//
//   console=ttyS0 reboot=k panic=1 root=/dev/ram0 rw -- lodash@4.17.21
//
// Defaults to lodash@4.17.21 (the Stage 1 acceptance package) if
// nothing is passed.
//
// Linked static-musl + libbpf-static so the initrd has no
// shared-library dependency on the loader itself. The guest also
// contains a full Alpine rootfs (busybox, musl, nodejs, npm) so the
// child `npm` process resolves its own libraries against the rootfs.

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
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <linux/reboot.h>

#include <bpf/libbpf.h>

#define EV_EXECVE  1
#define EV_CONNECT 2

#define AF_INET    2
#define AF_INET6  10

// Match probe.bpf.c
struct event {
	uint32_t type;
	uint32_t pid;
	uint32_t ppid;
	char     comm[16];
	union {
		struct { char filename[128]; } execve;
		struct {
			uint32_t family;
			uint32_t port;
			uint8_t  addr_v4[4];
			uint8_t  addr_v6[16];
		} conn;
	};
};

// ---- aggregation state ----

#define MAX_EXEC 256
#define MAX_CONN  64

static struct {
	char filename[128];
} exec_events[MAX_EXEC];
static int n_exec;

static struct {
	char     addr_str[64];
	uint32_t port;
} conn_events[MAX_CONN];
static int n_conn;

static uint64_t total_events;
static uint64_t ringbuf_drops;

static int handle_event(void *ctx, void *data, size_t data_sz)
{
	(void)ctx;
	if (data_sz < sizeof(struct event))
		return 0;
	struct event *e = data;
	total_events++;

	if (e->type == EV_EXECVE) {
		if (n_exec >= MAX_EXEC) {
			ringbuf_drops++;
			return 0;
		}
		memcpy(exec_events[n_exec].filename, e->execve.filename, 128);
		exec_events[n_exec].filename[127] = '\0';
		n_exec++;
	} else if (e->type == EV_CONNECT) {
		if (n_conn >= MAX_CONN) {
			ringbuf_drops++;
			return 0;
		}
		if (e->conn.family == AF_INET) {
			snprintf(conn_events[n_conn].addr_str, 64,
			         "%u.%u.%u.%u",
			         e->conn.addr_v4[0], e->conn.addr_v4[1],
			         e->conn.addr_v4[2], e->conn.addr_v4[3]);
		} else if (e->conn.family == AF_INET6) {
			char *p = conn_events[n_conn].addr_str;
			size_t left = 64;
			for (int i = 0; i < 8 && left > 0; i++) {
				int n = snprintf(p, left, "%s%x",
				                 i ? ":" : "",
				                 (e->conn.addr_v6[i*2] << 8) |
				                  e->conn.addr_v6[i*2+1]);
				if (n < 0 || (size_t)n >= left) break;
				p += n;
				left -= n;
			}
		} else {
			return 0;
		}
		conn_events[n_conn].port = e->conn.port;
		n_conn++;
	}
	return 0;
}

// ---- JSON output ----

static void json_escape(const char *src, char *dst, size_t dst_size)
{
	size_t j = 0;
	for (size_t i = 0; src[i] && j + 7 < dst_size; i++) {
		unsigned char c = (unsigned char)src[i];
		if (c == '"' || c == '\\') {
			dst[j++] = '\\';
			dst[j++] = c;
		} else if (c < 0x20 || c > 0x7e) {
			j += snprintf(dst + j, dst_size - j, "\\u%04x", c);
		} else {
			dst[j++] = c;
		}
	}
	dst[j] = '\0';
}

static int already_seen_exec(int idx)
{
	for (int j = 0; j < idx; j++)
		if (strcmp(exec_events[j].filename, exec_events[idx].filename) == 0)
			return 1;
	return 0;
}

static int already_seen_conn(int idx)
{
	for (int j = 0; j < idx; j++)
		if (strcmp(conn_events[j].addr_str, conn_events[idx].addr_str) == 0
		    && conn_events[j].port == conn_events[idx].port)
			return 1;
	return 0;
}

static void emit_fingerprint(const char *pkg, int exit_status,
                             long long duration_ms,
                             long long boot_to_install_ms,
                             const char *load_err)
{
	printf("DETONATION_BEGIN\n");
	printf("{");
	printf("\"package\":\"%s\",", pkg);
	printf("\"exit_status\":%d,", exit_status);
	printf("\"duration_ms\":%lld,", duration_ms);
	printf("\"boot_to_install_ms\":%lld,", boot_to_install_ms);
	printf("\"events_total\":%llu,", (unsigned long long)total_events);
	printf("\"ringbuf_drops\":%llu,", (unsigned long long)ringbuf_drops);
	if (load_err)
		printf("\"load_error\":\"%s\",", load_err);

	printf("\"execve_targets\":[");
	int printed = 0;
	for (int i = 0; i < n_exec; i++) {
		if (already_seen_exec(i)) continue;
		char escaped[260];
		json_escape(exec_events[i].filename, escaped, sizeof(escaped));
		printf("%s\"%s\"", printed ? "," : "", escaped);
		printed++;
	}
	printf("],");

	printf("\"connect_peers\":[");
	printed = 0;
	for (int i = 0; i < n_conn; i++) {
		if (already_seen_conn(i)) continue;
		printf("%s\"%s:%u\"",
		       printed ? "," : "",
		       conn_events[i].addr_str,
		       conn_events[i].port);
		printed++;
	}
	printf("]");

	printf("}\n");
	printf("DETONATION_END\n");
}

// ---- helpers ----

static long long now_ms(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

__attribute__((noreturn))
static void halt(void)
{
	fflush(stdout);
	sync();
	sleep(1);
	reboot(LINUX_REBOOT_CMD_RESTART);
	for (;;) pause();
}

// Read the value of a `key=value` argument from /proc/cmdline after
// the "--" init-args separator. Returns a malloc'd copy or NULL.
static char *cmdline_kv(const char *key)
{
	int fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0) return NULL;
	char buf[4096];
	ssize_t n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) return NULL;
	buf[n] = '\0';

	char *sep = strstr(buf, " -- ");
	if (!sep) return NULL;
	sep += 4;

	size_t klen = strlen(key);
	char needle[64];
	if (klen + 2 > sizeof(needle)) return NULL;
	snprintf(needle, sizeof(needle), "%s=", key);

	char *p = strstr(sep, needle);
	if (!p) return NULL;
	p += strlen(needle);
	char *end = strpbrk(p, " \n\r\t");
	size_t len = end ? (size_t)(end - p) : strlen(p);
	if (len == 0) return NULL;
	char *out = malloc(len + 1);
	if (!out) return NULL;
	memcpy(out, p, len);
	out[len] = '\0';
	return out;
}

// Fork+exec a command, wait, return exit status. Used to bring up
// the guest network via `ip` from the Alpine rootfs.
static int run_cmd(char *const argv[])
{
	pid_t p = fork();
	if (p < 0) return -1;
	if (p == 0) {
		execvp(argv[0], argv);
		// execvp returned: report the errno on stderr (serial) before
		// dying so we don't lose the diagnosis.
		fprintf(stderr, "execvp(%s) failed: %s (errno=%d)\n",
		        argv[0], strerror(errno), errno);
		_exit(127);
	}
	int status;
	if (waitpid(p, &status, 0) < 0) return -1;
	return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

// Configure eth0 using the guest_ip / host_ip / interface passed via
// cmdline kv pairs (ip=..., gw=...). Returns 0 on full success.
static int setup_network(void)
{
	char *guest_ip = cmdline_kv("guest_ip");
	char *gw       = cmdline_kv("gw");
	const char *iface = "eth0";
	if (!guest_ip || !gw) {
		fprintf(stderr, "setup_network: missing guest_ip or gw cmdline kv\n");
		free(guest_ip); free(gw);
		return -1;
	}
	char ip_cidr[64];
	snprintf(ip_cidr, sizeof(ip_cidr), "%s/24", guest_ip);

	int rc = 0;
	rc |= run_cmd((char *[]){"ip", "link", "set", (char *)iface, "up", NULL});
	rc |= run_cmd((char *[]){"ip", "addr", "add", ip_cidr, "dev", (char *)iface, NULL});
	rc |= run_cmd((char *[]){"ip", "route", "add", "default", "via", gw, NULL});

	free(guest_ip); free(gw);
	return rc;
}

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
	// keep WARN/ERROR on stderr; suppress INFO+DEBUG to keep serial clean
	if (level == LIBBPF_DEBUG || level == LIBBPF_INFO)
		return 0;
	return vfprintf(stderr, fmt, args);
}

// ---- main ----

int main(int argc, char **argv)
{
	(void)argc; (void)argv;

	long long t0 = now_ms();

	// Kernel starts /init with empty env. Set PATH first so the
	// downstream execvp("ip", ...) and execlp("npm", ...) can find
	// their binaries.
	setenv("PATH",
	       "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	       1);

	// PID 1: mount our own /proc, /sys, /dev, /sys/fs/bpf, tracefs.
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/dev", 0755);
	mount("proc",     "/proc", "proc",     0, NULL);
	mount("sysfs",    "/sys",  "sysfs",    0, NULL);
	mount("devtmpfs", "/dev",  "devtmpfs", 0, NULL);
	mkdir("/sys/fs/bpf", 0755);
	mount("bpf", "/sys/fs/bpf", "bpf", 0, NULL);
	mkdir("/sys/kernel/tracing", 0755);
	mount("tracefs", "/sys/kernel/tracing", "tracefs", 0, NULL);

	// tmpfs work dirs
	mkdir("/tmp", 0777);
	mount("tmpfs", "/tmp", "tmpfs", 0, "size=256m");
	mkdir("/install", 0755);
	mount("tmpfs", "/install", "tmpfs", 0, "size=512m");
	mkdir("/install/.home", 0755);

	// Bring up the guest network. LVH kernels don't necessarily have
	// CONFIG_IP_PNP=y so we can't rely on the kernel's `ip=` boot arg;
	// configure eth0 manually via busybox `ip` from the Alpine rootfs.
	int net_rc = setup_network();
	fprintf(stderr, "setup_network rc=%d\n", net_rc);

	// Determine which package to install
	char *pkg = cmdline_kv("pkg");
	const char *package = pkg ? pkg : "lodash@4.17.21";

	libbpf_set_print(libbpf_print_fn);

	struct bpf_object *obj = bpf_object__open_file("/probe.bpf.o", NULL);
	if (!obj || libbpf_get_error(obj)) {
		emit_fingerprint(package, -100, 0, now_ms() - t0, "open_failed");
		halt();
	}

	if (bpf_object__load(obj)) {
		emit_fingerprint(package, -101, 0, now_ms() - t0, "load_failed");
		halt();
	}

	// Attach every program in the object
	struct bpf_program *prog;
	bpf_object__for_each_program(prog, obj) {
		struct bpf_link *link = bpf_program__attach(prog);
		(void)link;  // intentionally leaked; we halt the VM at the end
	}

	struct bpf_map *map = bpf_object__find_map_by_name(obj, "events");
	if (!map) {
		emit_fingerprint(package, -102, 0, now_ms() - t0, "no_events_map");
		halt();
	}
	struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(map),
	                                          handle_event, NULL, NULL);
	if (!rb || libbpf_get_error(rb)) {
		emit_fingerprint(package, -103, 0, now_ms() - t0, "ringbuf_new_failed");
		halt();
	}

	long long t_load = now_ms();

	// npm env — point caches into /install so we can identify writes
	// outside the install root as "suspicious" (Stage 2 work).
	setenv("HOME", "/install/.home", 1);
	// PATH already set at top of main(); keep here as documentation.
	setenv("npm_config_prefix",          "/install",            1);
	setenv("npm_config_cache",           "/install/.npm-cache", 1);
	setenv("npm_config_userconfig",      "/install/.npmrc",     1);
	// Do NOT set npm_config_globalconfig to the same path —
	// npm refuses to "double-load" the same file as both user and
	// global config and exits before resolving the install.
	setenv("npm_config_update_notifier", "false",            1);

	long long t_install_start = now_ms();
	pid_t pid = fork();
	if (pid == 0) {
		// Child: run `npm install --prefix=/install --no-audit ... <pkg>`
		execlp("npm", "npm", "install",
		       "--prefix=/install",
		       "--no-audit", "--no-fund", "--no-progress",
		       package,
		       (char *)NULL);
		_exit(127);
	}

	// Parent: poll ringbuf until child exits
	int status = -1;
	if (pid > 0) {
		while (1) {
			pid_t r = waitpid(pid, &status, WNOHANG);
			if (r == pid)
				break;
			if (r < 0 && errno != EINTR)
				break;
			ring_buffer__poll(rb, 100);
		}
		// Drain anything still queued
		for (int i = 0; i < 20; i++) {
			if (ring_buffer__poll(rb, 100) <= 0)
				break;
		}
	}
	long long t_install_end = now_ms();

	int exit_status = -1;
	if (pid > 0 && WIFEXITED(status))
		exit_status = WEXITSTATUS(status);

	emit_fingerprint(package, exit_status,
	                 t_install_end - t_install_start,
	                 t_load - t0,
	                 NULL);

	halt();
}
