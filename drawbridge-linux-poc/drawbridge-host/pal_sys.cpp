/*
 * pal_sys.c — Component C10 (Time / Random / SysInfo / ProcessId).
 *
 * Translations of analysis/sqlservr_FULL.c:
 *   FUN_00202100 @ line 67430 — syscall-wrapper family.  The
 *                                DK_SystemTimeQuery branch maps to
 *                                clock_gettime → FILETIME below.
 *   FUN_003539f0 @ line 314242 — getpid thunk (FUN_003533e0 dispatch).
 *
 * See pal_sys.h for rationale.  dk_pal.c defines the DK_* names
 * strong; we therefore expose our translations as pal_sys_* (strong,
 * canonical) and provide *weak* DK_* aliases that call pal_sys_*.
 * When a future milestone dissolves dk_pal.c these weak symbols
 * become the live definitions with no code change here.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <sys/random.h>

#include "drawbridge_types.h"   /* DK_API, DK_HANDLE, DK_STATUS_* */
#include "pal_sys.h"

/* =============================================================
 * pal_sys_time_query — FUN_00202100 (clock/time branch)
 *
 * Windows FILETIME = 100ns ticks since 1601-01-01; the +11644473600s
 * offset bridges the Unix/Windows epoch gap.
 * ============================================================= */
int pal_sys_time_query(uint64_t clock_type, uint64_t *out_filetime)
{
    struct timespec ts;
    clockid_t clk = (clock_type == 0) ? CLOCK_REALTIME : CLOCK_MONOTONIC;
    if (clock_gettime(clk, &ts) != 0) return -1;

    uint64_t ft = ((uint64_t)ts.tv_sec + 11644473600ULL) * 10000000ULL
                + (uint64_t)ts.tv_nsec / 100;
    if (out_filetime) *out_filetime = ft;
    return 0;
}

/* =============================================================
 * pal_sys_random_read — getrandom(2) with short-read loop.
 * ============================================================= */
int pal_sys_random_read(void *buffer, uint64_t length)
{
    if (!buffer || length == 0) return 0;
    uint8_t *p = (uint8_t *)buffer;
    uint64_t remaining = length;
    while (remaining > 0) {
        ssize_t n = getrandom(p, remaining, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return -1;
        }
        p += n;
        remaining -= (uint64_t)n;
    }
    return 0;
}

/* =============================================================
 * pal_sys_info_query — sysconf + /proc/meminfo.
 *
 * 48-byte SYSTEM_INFO-shaped header:
 *   [0] page_size, [1] processor_count, [2] processor_arch (0x8664),
 *   [3] processor_level, [4..5] allocation_granularity,
 *   [6..7] total_physical_memory.
 * ============================================================= */
static uint64_t read_proc_meminfo_total_bytes(void)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    uint64_t total_kb = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "MemTotal:", 9) == 0) {
            sscanf(line + 9, " %lu", (unsigned long *)&total_kb);
            break;
        }
    }
    fclose(f);
    return total_kb * 1024ULL;
}

int pal_sys_info_query(uint64_t info_class, void *buffer,
                       uint64_t buffer_size, uint64_t *out_result_size)
{
    (void)info_class;
    if (buffer && buffer_size >= 48) {
        memset(buffer, 0, buffer_size > 256 ? 256 : buffer_size);
        uint32_t *info = (uint32_t *)buffer;
        info[0] = (uint32_t)sysconf(_SC_PAGESIZE);
        long np = sysconf(_SC_NPROCESSORS_ONLN);
        info[1] = (uint32_t)(np > 0 ? np : 1);
        info[2] = 0x8664;
        info[3] = 6;
        *(uint64_t *)(info + 4) = 0x10000;

        uint64_t total = read_proc_meminfo_total_bytes();
        if (total == 0) {
            total = (uint64_t)sysconf(_SC_PHYS_PAGES)
                  * (uint64_t)sysconf(_SC_PAGESIZE);
        }
        *(uint64_t *)(info + 6) = total;
    }
    if (out_result_size) *out_result_size = 48;
    return 0;
}

/* =============================================================
 * pal_sys_process_get_id — FUN_003539f0 (ELF thunk → getpid).
 * ============================================================= */
uint64_t pal_sys_process_get_id(void)
{
    return (uint64_t)getpid();
}

/* =============================================================
 * Weak DK_* aliases routed through pal_sys_*.
 *
 * dk_pal.c defines the DK_* names strong today; these weak
 * definitions exist so a future plan that removes dk_pal.c from the
 * TU list gets live DK_* symbols with no code change here.  With
 * --allow-multiple-definition the linker's first-seen wins, and
 * pal_sys.c precedes dk_pal.c in Makefile SRCS for exactly this
 * reason.
 * ============================================================= */
#define PAL_WEAK __attribute__((weak))

PAL_WEAK DK_API uint64_t DK_SystemTimeQuery(uint64_t clock_type,
                                            uint64_t *time_val)
{
    return pal_sys_time_query(clock_type, time_val) == 0
         ? DK_STATUS_SUCCESS : DK_STATUS_INVALID_PARAM;
}

PAL_WEAK DK_API uint64_t DK_RandomBitsRead(void *buffer, uint64_t length)
{
    return pal_sys_random_read(buffer, length) == 0
         ? DK_STATUS_SUCCESS : DK_STATUS_INVALID_PARAM;
}

PAL_WEAK DK_API uint64_t DK_SystemInfoQuery(uint64_t info_class, void *buffer,
                                            uint64_t buffer_size,
                                            uint64_t *result_size)
{
    (void)pal_sys_info_query(info_class, buffer, buffer_size, result_size);
    return DK_STATUS_SUCCESS;
}

PAL_WEAK DK_API uint64_t DK_ProcessGetId(uint64_t *pid)
{
    if (pid) *pid = pal_sys_process_get_id();
    return DK_STATUS_SUCCESS;
}
