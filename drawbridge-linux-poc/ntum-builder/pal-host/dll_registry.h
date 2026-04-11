/*
 * DLL Registry - Manages loaded PE DLLs for import resolution
 *
 * When a target .exe imports from e.g. kernel32.dll, we:
 * 1. Check if a real DLL (from ReactOS) is loaded in the registry
 * 2. If yes, resolve the import from the DLL's export table
 * 3. If no, fall back to our Win32 stub implementations
 *
 * This is how we incrementally replace stubs with real ReactOS DLLs.
 */

#ifndef DLL_REGISTRY_H
#define DLL_REGISTRY_H

#include "pe_loader.h"

#define MAX_LOADED_DLLS 64

typedef struct {
    char name[64];              /* DLL name (e.g. "kernel32.dll") */
    pe_loaded_image_t image;    /* Loaded PE image */
    int initialized;            /* DllMain called? */
} loaded_dll_t;

typedef struct {
    loaded_dll_t dlls[MAX_LOADED_DLLS];
    int count;
    const char *dll_search_path;    /* Where to find ReactOS DLLs */
    import_resolver_fn stub_resolver; /* Fallback stub resolver */
    void *stub_ctx;
} dll_registry_t;

/* Initialize the DLL registry */
void dll_registry_init(dll_registry_t *reg, const char *search_path,
                       import_resolver_fn stub_resolver, void *stub_ctx);

/* Pre-load a DLL from disk into the registry */
int dll_registry_load(dll_registry_t *reg, const char *dll_name);

/* Load all .dll files from the search path */
int dll_registry_load_all(dll_registry_t *reg);

/* Resolve an import: check loaded DLLs first, then fall back to stubs */
void *dll_registry_resolve(const char *dll_name, const char *func_name,
                           uint16_t ordinal, void *ctx);

/* Get the registry (for passing as ctx to dll_registry_resolve) */
dll_registry_t *dll_registry_get(void);

#endif /* DLL_REGISTRY_H */
