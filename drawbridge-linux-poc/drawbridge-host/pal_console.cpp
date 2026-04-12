/*
 * pal_console.cpp — Component C11: Console bring-up.
 *
 * Provides the strong definition of DK_ConsoleCreate. The NTUM calls
 * this very early during boot (func_id 0x6001000) to obtain a handle
 * it can later write "hello from drawbridge" to via DK_StreamWrite.
 *
 * We return the raw host stdout fd as the DK handle. pal_stream.cpp's
 * DK_StreamWrite fast-paths handle == STDOUT_FILENO (1) /
 * STDERR_FILENO (2) to a direct write(2), so no handle-pool lookup is
 * needed for this critical boot print.
 *
 * Decompiled reference: the ELF host performs the same bind in
 * FUN_00204680 (sqlservr_FULL.c:69308) where the guest parameter
 * block's std-stream slots are populated.
 */

#include "pal_console.h"

#include <stdio.h>
#include <unistd.h>

extern "C" {

DK_API uint64_t DK_ConsoleCreate(DK_HANDLE *out_console_handle) {
    if (!out_console_handle) return DK_STATUS_INVALID_PARAM;
    /* Handle 1 == STDOUT_FILENO; DK_StreamWrite recognises this. */
    *out_console_handle = (DK_HANDLE)STDOUT_FILENO;
    return DK_STATUS_SUCCESS;
}

} /* extern "C" */
