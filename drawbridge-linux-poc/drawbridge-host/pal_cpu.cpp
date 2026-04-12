/*
 * pal_cpu.cpp — Component C16 (Processor Topology / NUMA).
 *
 * Translated from analysis/sqlservr_FULL.c:
 *   FUN_002065f0 @ line 71065..71280  — ProcessorTopology::Initialize.
 *     • reads /proc/cpuinfo (FUN_003536b0("/proc/cpuinfo",0))
 *     • calls sysconf(_SC_NPROCESSORS_ONLN) via FUN_00353a10(0x54)
 *     • walks NUMA via FUN_003542e0 / FUN_003542f0
 *     • logs "NUMA information not available, assuming one NUMA node"
 *   FUN_0028a620 @ line 157880..157941 — GuestCpu::RefreshAffinity
 *     • sched_getaffinity on &DAT_00461548 (128-byte mask)
 *     • logs "sched_getaffinity failed with error %d"
 *
 * This file is compiled *before* dk_pal.cpp in the Makefile so its
 * strong DK_ThreadSetAffinity / DK_SystemInfoQuery definitions win
 * under -Wl,--allow-multiple-definition (first-seen rule).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>

#include "pal_cpu.h"

/* =============================================================
 * Struct-layout static assertions (rule 3).
 *
 * The PE's kernel32 replica memcpy's our DK_SYSTEM_INFO buffer
 * straight into its Win32 SYSTEM_INFO.  These offsets are
 * load-bearing.
 * ============================================================= */
static_assert(sizeof(DK_SYSTEM_INFO) == 0x30,
              "DK_SYSTEM_INFO must be exactly 48 bytes");
static_assert(offsetof(DK_SYSTEM_INFO, wProcessorArchitecture) == 0x00,
              "wProcessorArchitecture @ +0x00");
static_assert(offsetof(DK_SYSTEM_INFO, dwPageSize) == 0x04,
              "dwPageSize @ +0x04");
static_assert(offsetof(DK_SYSTEM_INFO, lpMinimumApplicationAddress) == 0x08,
              "lpMinimumApplicationAddress @ +0x08");
static_assert(offsetof(DK_SYSTEM_INFO, lpMaximumApplicationAddress) == 0x10,
              "lpMaximumApplicationAddress @ +0x10");
static_assert(offsetof(DK_SYSTEM_INFO, dwActiveProcessorMask) == 0x18,
              "dwActiveProcessorMask @ +0x18");
static_assert(offsetof(DK_SYSTEM_INFO, dwNumberOfProcessors) == 0x20,
              "dwNumberOfProcessors @ +0x20");
static_assert(offsetof(DK_SYSTEM_INFO, dwProcessorType) == 0x24,
              "dwProcessorType @ +0x24");
static_assert(offsetof(DK_SYSTEM_INFO, dwAllocationGranularity) == 0x28,
              "dwAllocationGranularity @ +0x28");
static_assert(offsetof(DK_SYSTEM_INFO, wProcessorLevel) == 0x2C,
              "wProcessorLevel @ +0x2C");
static_assert(offsetof(DK_SYSTEM_INFO, wProcessorRevision) == 0x2E,
              "wProcessorRevision @ +0x2E");

/* =============================================================
 * Helpers — parse /proc/cpuinfo & /sys/devices/system/node.
 * ============================================================= */

static uint32_t parse_proc_cpuinfo_count(void)
{
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return 0;
    char   line[512];
    uint32_t n = 0;
    while (fgets(line, sizeof(line), f)) {
        /* Each logical CPU is announced by a "processor" line. */
        if (strncmp(line, "processor", 9) == 0) {
            const char *colon = strchr(line, ':');
            if (colon) n++;
        }
    }
    fclose(f);
    return n;
}

static uint32_t scan_numa_nodes(void)
{
    DIR *d = opendir("/sys/devices/system/node");
    if (!d) return 1;        /* "NUMA information not available,
                                assuming one NUMA node" */
    uint32_t n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        if (strncmp(de->d_name, "node", 4) == 0 &&
            de->d_name[4] && isdigit((unsigned char)de->d_name[4])) {
            n++;
        }
    }
    closedir(d);
    return n == 0 ? 1 : n;
}

static int read_node_cpulist(uint32_t node, char *out, size_t cap)
{
    char path[128];
    snprintf(path, sizeof(path),
             "/sys/devices/system/node/node%u/cpulist", node);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t len = fread(out, 1, cap - 1, f);
    fclose(f);
    out[len] = '\0';
    return 0;
}

/* cpulist format: "0-3,8,12-15\n".  Returns true iff cpu is in it. */
static bool cpulist_contains(const char *list, uint32_t cpu)
{
    const char *p = list;
    while (*p) {
        while (*p == ' ' || *p == ',' || *p == '\n') p++;
        if (!*p) break;
        char *endp;
        long a = strtol(p, &endp, 10);
        long b = a;
        if (*endp == '-') {
            p = endp + 1;
            b = strtol(p, &endp, 10);
        }
        p = endp;
        if ((long)cpu >= a && (long)cpu <= b) return true;
    }
    return false;
}

/* =============================================================
 * PalCpuTopology — singleton cache loaded at startup.
 * ============================================================= */

PalCpuTopology &PalCpuTopology::instance()
{
    static PalCpuTopology s_instance;
    return s_instance;
}

PalCpuTopology::PalCpuTopology()
    : m_logical_count(0),
      m_numa_count(1),
      m_page_size(4096),
      m_alloc_granularity(0x10000),
      m_total_phys_bytes(0)
{
    for (size_t i = 0; i < sizeof(m_node_of_cpu) / sizeof(m_node_of_cpu[0]); i++) {
        m_node_of_cpu[i] = -1;
    }
    load();
}

void PalCpuTopology::load()
{
    /* Prefer /proc/cpuinfo (matches FUN_002065f0's path at line 71199). */
    m_logical_count = parse_proc_cpuinfo_count();
    if (m_logical_count == 0) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        m_logical_count = (n > 0) ? (uint32_t)n : 1;
    }
    if (m_logical_count > 1024) m_logical_count = 1024;

    long pg = sysconf(_SC_PAGESIZE);
    m_page_size = (pg > 0) ? (uint32_t)pg : 4096;
    /* Windows allocation granularity is 64 KiB and the PE hard-codes
     * this assumption in many places. */
    m_alloc_granularity = 0x10000;

    long phys_pages = sysconf(_SC_PHYS_PAGES);
    if (phys_pages > 0) {
        m_total_phys_bytes = (uint64_t)phys_pages * (uint64_t)m_page_size;
    }

    m_numa_count = scan_numa_nodes();

    /* Map each cpu → node. */
    for (uint32_t node = 0; node < m_numa_count; node++) {
        char buf[4096];
        if (read_node_cpulist(node, buf, sizeof(buf)) != 0) continue;
        for (uint32_t cpu = 0; cpu < m_logical_count; cpu++) {
            if (cpulist_contains(buf, cpu)) {
                m_node_of_cpu[cpu] = (int)node;
            }
        }
    }
}

int PalCpuTopology::node_of_cpu(uint32_t cpu) const
{
    if (cpu >= m_logical_count) return -1;
    return m_node_of_cpu[cpu];
}

/* =============================================================
 * Plain-C convenience wrappers.
 * ============================================================= */

extern "C" void pal_cpu_topology_init(void)
{
    (void)PalCpuTopology::instance();
}

extern "C" uint32_t pal_cpu_count_logical(void)
{
    return PalCpuTopology::instance().logical_count();
}

extern "C" uint32_t pal_cpu_count_numa_nodes(void)
{
    return PalCpuTopology::instance().numa_count();
}

extern "C" int pal_cpu_node_of_processor(uint32_t cpu)
{
    return PalCpuTopology::instance().node_of_cpu(cpu);
}

extern "C" int pal_cpu_get_affinity(int pid, void *mask_1024)
{
    if (!mask_1024) { errno = EINVAL; return -1; }
    /* glibc's cpu_set_t is 128 bytes; matches the NTUM's 0x80-byte
     * buffer at DAT_00461548. */
    memset(mask_1024, 0, 128);
    if (sched_getaffinity((pid_t)pid, 128, (cpu_set_t *)mask_1024) != 0) {
        return -1;
    }
    return 0;
}

extern "C" int pal_cpu_set_affinity(int pid, const void *mask_1024)
{
    if (!mask_1024) { errno = EINVAL; return -1; }
    if (sched_setaffinity((pid_t)pid, 128,
                          (const cpu_set_t *)mask_1024) != 0) {
        return -1;
    }
    return 0;
}

/* =============================================================
 * Strong DK_* overrides (extern "C", ms_abi).
 *
 * These win over dk_pal.cpp's stubs because this translation unit
 * precedes dk_pal.cpp in the Makefile SRCS list and the linker is
 * invoked with -Wl,--allow-multiple-definition.
 * ============================================================= */

extern "C" DK_API uint64_t
DK_ThreadSetAffinity(DK_HANDLE thread, uint64_t group, uint64_t mask)
{
    /* Windows affinity = (group, mask) where each group covers up to
     * 64 processors.  Translate to a Linux cpu_set_t bitmap. */
    (void)thread;                 /* NTUM always asks for current thread
                                     in practice; group handle support
                                     would require a DK_HANDLE→pthread
                                     lookup we don't yet maintain here. */
    if (group >= 16) return DK_STATUS_INVALID_PARAM;  /* 16*64 = 1024 */
    if (mask == 0)   return DK_STATUS_INVALID_PARAM;  /* "Group mask is
                                                         empty", line 73872 */
    uint64_t cpu_mask[16] = {0};
    cpu_mask[group] = mask;

    /* 0 → current thread (tid via gettid for per-thread affinity). */
    pid_t tid = (pid_t)syscall(SYS_gettid);
    if (sched_setaffinity(tid, sizeof(cpu_mask),
                          (cpu_set_t *)cpu_mask) != 0) {
        return DK_STATUS_INVALID_PARAM;
    }
    return DK_STATUS_SUCCESS;
}

extern "C" DK_API uint64_t
DK_SystemInfoQuery(uint64_t info_class, void *buffer,
                   uint64_t buffer_size, uint64_t *result_size)
{
    (void)info_class;
    if (!buffer || buffer_size < sizeof(DK_SYSTEM_INFO)) {
        if (result_size) *result_size = sizeof(DK_SYSTEM_INFO);
        return DK_STATUS_INVALID_PARAM;
    }

    PalCpuTopology &topo = PalCpuTopology::instance();
    DK_SYSTEM_INFO si;
    memset(&si, 0, sizeof(si));

    si.wProcessorArchitecture    = 0x0009;        /* PROCESSOR_ARCHITECTURE_AMD64 */
    si.dwPageSize                = topo.page_size();
    si.lpMinimumApplicationAddress = (void *)0x0000000000010000ULL;
    si.lpMaximumApplicationAddress = (void *)0x00007FFFFFFEFFFFULL;
    uint32_t cpus                = topo.logical_count();
    if (cpus > 64) cpus = 64;
    si.dwActiveProcessorMask     = (cpus >= 64) ? ~0ULL
                                                : ((1ULL << cpus) - 1);
    si.dwNumberOfProcessors      = topo.logical_count();
    si.dwProcessorType           = 8664;          /* PROCESSOR_AMD_X8664 */
    si.dwAllocationGranularity   = topo.alloc_granularity();
    si.wProcessorLevel           = 6;
    si.wProcessorRevision        = 0;

    memcpy(buffer, &si, sizeof(si));
    if (result_size) *result_size = sizeof(si);
    return DK_STATUS_SUCCESS;
}

/* =============================================================
 * Eager topology init at library-load time.  Doing it here avoids
 * the first DK_SystemInfoQuery call paying the /proc parse cost on
 * a critical path.
 * ============================================================= */
namespace {
struct PalCpuAutoInit {
    PalCpuAutoInit() { pal_cpu_topology_init(); }
};
static PalCpuAutoInit s_pal_cpu_auto_init;
} /* namespace */
