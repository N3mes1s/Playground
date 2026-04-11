/*
 * NTUM PAL Interface
 *
 * This defines the ~30 primitive operations that the NTUM kernel
 * calls into the Linux PAL host. This is the Drawbridge "narrow waist".
 *
 * In the real SQLPAL, these are implemented as callbacks from the PE
 * world into the ELF host. We use a function pointer table stored at
 * a known address in the NTUM's address space.
 */

#ifndef NTUM_PAL_H
#define NTUM_PAL_H

#include <stdint.h>
#include <stddef.h>

/* PAL handle type */
typedef uint64_t PAL_HANDLE;
#define PAL_INVALID_HANDLE ((PAL_HANDLE)-1)

/* PAL status codes */
#define PAL_SUCCESS      0
#define PAL_ERROR       -1

/* Memory protection flags */
#define PAL_PROT_NONE    0x00
#define PAL_PROT_READ    0x01
#define PAL_PROT_WRITE   0x02
#define PAL_PROT_EXEC    0x04

/* Stream open modes */
#define PAL_STREAM_READ    0x01
#define PAL_STREAM_WRITE   0x02
#define PAL_STREAM_CREATE  0x04
#define PAL_STREAM_APPEND  0x08

/*
 * PAL Function Table
 *
 * The PAL host fills this table and passes a pointer to it
 * when initializing the NTUM. The NTUM uses these functions
 * for all host interactions.
 */
typedef struct _PAL_TABLE {
    uint32_t version;       /* PAL ABI version */
    uint32_t num_entries;   /* Number of entries in table */

    /* Memory management */
    void *(*mem_alloc)(void *addr, size_t size, int prot);
    int   (*mem_free)(void *addr, size_t size);
    int   (*mem_protect)(void *addr, size_t size, int prot);

    /* I/O streams (files, pipes, network) */
    PAL_HANDLE (*stream_open)(const char *uri, int mode);
    int64_t    (*stream_read)(PAL_HANDLE stream, void *buf, size_t count);
    int64_t    (*stream_write)(PAL_HANDLE stream, const void *buf, size_t count);
    int        (*stream_close)(PAL_HANDLE stream);
    int        (*stream_flush)(PAL_HANDLE stream);
    int64_t    (*stream_size)(PAL_HANDLE stream);
    void      *(*stream_map)(PAL_HANDLE stream, size_t offset, size_t size, int prot);

    /* Threading */
    PAL_HANDLE (*thread_create)(void (*fn)(void*), void *arg, size_t stack_size);
    void       (*thread_exit)(int code);
    int        (*thread_join)(PAL_HANDLE thread);
    uint64_t   (*thread_id)(void);

    /* Synchronization */
    PAL_HANDLE (*event_create)(int initial_state);
    int        (*event_set)(PAL_HANDLE event);
    int        (*event_reset)(PAL_HANDLE event);
    int        (*event_wait)(PAL_HANDLE event, int timeout_ms);
    PAL_HANDLE (*mutex_create)(void);
    int        (*mutex_lock)(PAL_HANDLE mutex);
    int        (*mutex_unlock)(PAL_HANDLE mutex);
    void       (*mutex_destroy)(PAL_HANDLE mutex);

    /* Process */
    void       (*process_exit)(int code);
    uint64_t   (*process_id)(void);

    /* Time */
    uint64_t   (*time_query)(void);         /* microseconds since epoch */
    uint64_t   (*time_monotonic)(void);     /* monotonic microseconds */
    void       (*time_sleep)(uint64_t us);

    /* System info */
    int        (*cpu_count)(void);
    uint64_t   (*memory_total)(void);

    /* Entropy */
    int        (*random_read)(void *buf, size_t count);

    /* Console */
    int64_t    (*console_write)(const void *buf, size_t count);
    int64_t    (*console_error)(const void *buf, size_t count);

    /* PE loading (host provides PE loader) */
    void      *(*load_pe)(const char *path, void **entry_point);
    int        (*resolve_import)(const char *dll_name, const char *func_name,
                                 void **out_addr);

    /* Debug */
    void       (*debug_print)(const char *msg);

} PAL_TABLE;

/*
 * NTUM initialization parameters (passed from host to NTUM)
 */
typedef struct _NTUM_INIT_PARAMS {
    PAL_TABLE *pal;                 /* Pointer to PAL function table */
    const char *system_root;        /* Path to Windows System32 directory */
    const char *registry_hive;      /* Path to registry hive file */
    const char *target_exe;         /* Path to the target .exe to run */
    int argc;                       /* Command line argc for target */
    const char **argv;              /* Command line argv for target */
} NTUM_INIT_PARAMS;

/*
 * NTUM entry point (called by the PAL host to start the kernel)
 * Returns: exit code from the target application
 */
typedef int (*ntum_entry_fn)(NTUM_INIT_PARAMS *params);

#endif /* NTUM_PAL_H */
