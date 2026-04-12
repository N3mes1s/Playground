/*
 * pal_cpu.h — Component C16 (Processor Topology / NUMA).
 *
 * Translations of analysis/sqlservr_FULL.c:
 *   ProcessorTopology.cpp references around lines 71053..74117
 *     (FUN_002065f0 — reads /proc/cpuinfo, walks NUMA nodes).
 *   native/GuestCpu.cpp around line 157898 — sched_getaffinity
 *     wrapper (FUN_0028a620).
 *   sysconf(_SC_NPROCESSORS_ONLN) is invoked via FUN_00353a10(0x54).
 *
 * The NTUM queries this topology during boot (DK_SystemInfoQuery,
 * func_id 0x8003000) and whenever it creates scheduler nodes.
 * A strong override for DK_ThreadSetAffinity translates Win32-style
 * (group, mask) affinities into Linux cpu_set_t via sched_setaffinity.
 *
 * Exposed as a small C++ class (PalCpuTopology) cached at startup;
 * the DK_* entry points are extern "C" with ms_abi.
 */

#ifndef PAL_CPU_H
#define PAL_CPU_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "drawbridge_types.h"

/* =============================================================
 * Plain C API — small helpers other PAL files may call.
 * ============================================================= */

/* Number of logical CPUs online.  Parses /proc/cpuinfo; falls back
 * to sysconf(_SC_NPROCESSORS_ONLN). */
uint32_t pal_cpu_count_logical(void);

/* Number of NUMA nodes. Walks /sys/devices/system/node/node%d.
 * Returns 1 when NUMA information is not available. */
uint32_t pal_cpu_count_numa_nodes(void);

/* NUMA node id for a given logical processor (reads
 * /sys/devices/system/node/node%d/cpulist).  Returns -1 on error. */
int pal_cpu_node_of_processor(uint32_t cpu);

/* sched_getaffinity wrapper.  pid==0 → current thread.
 * mask is a pointer to a 1024-bit (128-byte) bitmap (cpu_set_t style).
 * Returns 0 on success, -1 on error. */
int pal_cpu_get_affinity(int pid, void *mask_1024);

/* sched_setaffinity wrapper.  Same convention as above. */
int pal_cpu_set_affinity(int pid, const void *mask_1024);

/* Ensures the cached topology is loaded (idempotent, thread-safe). */
void pal_cpu_topology_init(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#ifdef __cplusplus

/* =============================================================
 * C++ topology cache.
 * ============================================================= */

class PalCpuTopology {
public:
    static PalCpuTopology &instance();

    uint32_t logical_count() const  { return m_logical_count; }
    uint32_t numa_count()    const  { return m_numa_count;    }
    uint32_t page_size()     const  { return m_page_size;     }
    uint32_t alloc_granularity() const { return m_alloc_granularity; }
    uint64_t total_phys_bytes() const  { return m_total_phys_bytes; }

    /* NUMA node id for a given cpu (or -1). */
    int node_of_cpu(uint32_t cpu) const;

private:
    PalCpuTopology();
    void load();

    uint32_t m_logical_count;
    uint32_t m_numa_count;
    uint32_t m_page_size;
    uint32_t m_alloc_granularity;
    uint64_t m_total_phys_bytes;

    /* Per-CPU NUMA node table (indexed 0..m_logical_count-1). */
    int      m_node_of_cpu[1024];
};

#endif /* __cplusplus */

/* =============================================================
 * SYSTEM_INFO layout expected by the PE (Windows-compatible).
 *
 * Derived from the Win32 SYSTEM_INFO structure (WinBase.h) which
 * is what the PE's kernel32 replica expects from
 * DK_SystemInfoQuery (func_id 0x8003000).  The NTUM populates its
 * own copy at boot from these fields.
 * ============================================================= */

#ifdef __cplusplus
extern "C" {
#endif

#pragma pack(push, 1)
typedef struct DK_SYSTEM_INFO {
    uint16_t wProcessorArchitecture;   /* +0x00  0x9 = AMD64 */
    uint16_t wReserved;                /* +0x02 */
    uint32_t dwPageSize;               /* +0x04 */
    void    *lpMinimumApplicationAddress; /* +0x08 */
    void    *lpMaximumApplicationAddress; /* +0x10 */
    uint64_t dwActiveProcessorMask;    /* +0x18 */
    uint32_t dwNumberOfProcessors;     /* +0x20 */
    uint32_t dwProcessorType;          /* +0x24 */
    uint32_t dwAllocationGranularity;  /* +0x28 */
    uint16_t wProcessorLevel;          /* +0x2C */
    uint16_t wProcessorRevision;       /* +0x2E */
} DK_SYSTEM_INFO;                      /* sizeof == 0x30 (48) */
#pragma pack(pop)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* PAL_CPU_H */
