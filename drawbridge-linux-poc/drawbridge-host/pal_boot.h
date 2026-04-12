/*
 * pal_boot.h — Public interface for component C2 (Boot Orchestrator).
 *
 * Translations of analysis/sqlservr_FULL.c boot helpers:
 *   FUN_00354250 @ 315716 — pal_runtime_params_init
 *   FUN_00354260 @ 315727 — pal_runtime_params_commit
 *   FUN_00279cd0 @ 148635 — pal_logging_init
 *   FUN_001bd660 @  11011 — pal_threading_needed
 *   FUN_0021a7d0 @  87323 — pal_dynlink_init
 *   FUN_0021d1c0 @  88826 — pal_module_loader_init
 *   FUN_0021a750           — pal_library_init
 *   FUN_00353a90 @ 314352 — pal_setrlimit
 *   FUN_00354270 @ 315738 — pal_fd_limit_get
 *   FUN_00354280 @ 315749 — pal_fd_limit_set
 *   FUN_00279f10 @ 148701 — pal_io_finalize
 *   FUN_00204da0 @  69609 — pal_kernel_version_log
 *
 * Every symbol below is defined strong in pal_boot.c so that at link
 * time it supersedes the fail-loud placeholder in pal_stubs.c.
 */

#ifndef PAL_BOOT_H
#define PAL_BOOT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FUN_00354250 / FUN_00354260 — setrlimit wrapper chain that caps the
 * host's resource limits before boot.  In the ELF these are tiny
 * thunks into FUN_003533e0 (the raw syscall dispatcher); on Linux
 * they correspond to getrlimit / setrlimit scoping.  Our translation
 * applies the sane upper bounds the ELF host uses at runtime. */
void pal_runtime_params_init(void);
void pal_runtime_params_commit(void);

/* FUN_00279cd0 — trace infrastructure init.  In sqlservr this lights
 * up the logging-server channels; on Linux we init a stderr-backed
 * trace shim that downstream pal_trace_* callers key off of. */
void pal_logging_init(uint8_t debug_flag);

/* FUN_001bd660 — "does this image want background threading?".
 * Returns 1 if the image handle supports threading (our host answer:
 * always yes — sqlpal.dll needs the logger thread). */
char pal_threading_needed(void *image_handle);

/* FUN_0021a7d0 — dl_iterate_phdr-equivalent dynamic-link init. */
void pal_dynlink_init(void);

/* FUN_0021d1c0 — module loader setup. */
int  pal_module_loader_init(void);

/* FUN_0021a750 — library init pass (runs after dynlink). */
void pal_library_init(void);

/* FUN_00353a90 — setrlimit(2) wrapper. 'which' is the RLIMIT_* id
 * the ELF uses (1=DATA, 2=STACK historically); soft/hard are rlim_t. */
int  pal_setrlimit(int which, int soft, int hard);

/* FUN_00354270 / FUN_00354280 — getrlimit / setrlimit on NOFILE. */
int  pal_fd_limit_get(int resource, void *out_rlimit);
int  pal_fd_limit_set(int resource, const void *in_rlimit);

/* FUN_00279f10 — finalize the trace subsystem (flush buffers). */
void pal_io_finalize(void);

/* FUN_00204da0 — uname(2) + log. */
void pal_kernel_version_log(void);

#ifdef __cplusplus
}
#endif

#endif /* PAL_BOOT_H */
