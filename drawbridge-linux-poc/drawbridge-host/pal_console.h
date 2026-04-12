/*
 * pal_console.h — Component C11: Console bring-up.
 *
 * Wraps host stdout/stderr/stdin descriptors as DK stream handles so
 * the NTUM's early-boot "hello from drawbridge" print reaches real
 * write(2). The ELF host does the same bind-up as part of its
 * FUN_00204680 boot orchestrator (sqlservr_FULL.c:69308) where the
 * parameter block's input/output/error stream pointers are filled.
 *
 * Only one public entry is exposed through the DK ABI:
 *   DK_ConsoleCreate  (func_id 0x6001000)
 * which delegates to pal_stream_wrap_fd(STDOUT_FILENO, 0).
 */

#ifndef PAL_CONSOLE_H
#define PAL_CONSOLE_H

#include "dk_pal.h"

#endif /* PAL_CONSOLE_H */
