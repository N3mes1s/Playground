/*
 * pe_loader.h — Component C1 public interface (PE Loader & SFP).
 *
 * Source: carved out of drawbridge-host/main.c per plan
 * /root/.claude/plans/hashed-sparking-lake.md (Milestone M7).
 *
 * SFP parser + map_pe_from_sfp + PE header parsing.  Owns
 * drawbridge_types.h's sfp_archive_t / pe_*_header_t usage site.
 */

#ifndef PE_LOADER_H
#define PE_LOADER_H

#include <stdint.h>
#include "drawbridge_types.h"

/* Initialize any module-local state.  Kept as a no-op today so main.c
 * can call it at boot before LibOS memory + SFPs are wired up. */
void pe_loader_init(void);

/* Load an SFP archive from disk.  Matches the original main.c
 * static load_sfp() — opens the file, reads the header, pulls the
 * name table into heap.  Returns 0 on success. */
int  pe_loader_load_sfp(const char *path, sfp_archive_t *archive);

/* Look up a file in an SFP archive by (case-insensitive) name.
 * On success fills *data_offset / *data_size and returns 0. */
int  pe_loader_sfp_find_file(sfp_archive_t *archive, const char *name,
                             uint64_t *data_offset, uint64_t *data_size);

/* Map a PE file from within an SFP archive into the LibOS address
 * range.  Returns a pointer to the PE data at its real offset
 * (base_hint + offset_adj) or NULL on failure.  If base_hint is NULL
 * an address in the high kernel-control range is auto-assigned. */
void *pe_loader_map_pe_from_sfp(sfp_archive_t *archive, const char *name,
                                void *base_hint);

/* Map sqlpal.dll (or any PE64) at its preferred ImageBase, copy the
 * PE headers, copy each section from raw_pe_data into the image
 * region.
 *
 * Inputs:
 *   raw_pe_data       — pointer to the mmap'd SFP region for the PE.
 * Outputs (all non-NULL):
 *   *out_image_base   — mapped base address (PE's preferred ImageBase).
 *   *out_size_of_image — SizeOfImage from optional header.
 *   *out_entry_rva    — AddressOfEntryPoint.
 *   *out_raw_size     — highest (PointerToRawData + SizeOfRawData) byte
 *                       seen, useful for signal-handler demand-paging.
 *
 * Returns the final mapped image pointer, or NULL on failure.
 */
void *pe_loader_parse_and_map(void *raw_pe_data,
                              void **out_image_base,
                              uint32_t *out_size_of_image,
                              uint32_t *out_entry_rva,
                              size_t *out_raw_size);

/* Perform the LibOS memory-region pre-allocations (control pages,
 * kernel heap, app heap, KUSER_SHARED_DATA, etc.) that main.c used to
 * do inline via setup_libos_memory(). */
int  pe_loader_setup_libos_memory(void);

#endif /* PE_LOADER_H */
