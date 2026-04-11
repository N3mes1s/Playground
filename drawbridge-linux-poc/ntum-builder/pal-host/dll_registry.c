/*
 * DLL Registry Implementation
 *
 * Loads ReactOS DLLs and provides import resolution against them.
 * Falls back to our Win32 stubs for any function not found in real DLLs.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>

#include "dll_registry.h"

static dll_registry_t *g_registry = NULL;

/* Case-insensitive string compare */
static int dll_stricmp(const char *a, const char *b) {
    while (*a && *b) {
        char ca = (*a >= 'A' && *a <= 'Z') ? *a + 32 : *a;
        char cb = (*b >= 'A' && *b <= 'Z') ? *b + 32 : *b;
        if (ca != cb) return ca - cb;
        a++; b++;
    }
    return *a - *b;
}

void dll_registry_init(dll_registry_t *reg, const char *search_path,
                       import_resolver_fn stub_resolver, void *stub_ctx) {
    memset(reg, 0, sizeof(*reg));
    reg->dll_search_path = search_path;
    reg->stub_resolver = stub_resolver;
    reg->stub_ctx = stub_ctx;
    g_registry = reg;
}

int dll_registry_load(dll_registry_t *reg, const char *dll_name) {
    if (reg->count >= MAX_LOADED_DLLS) {
        fprintf(stderr, "[DLL] Registry full, cannot load %s\n", dll_name);
        return -1;
    }

    /* Build full path */
    char path[512];
    snprintf(path, sizeof(path), "%s/%s", reg->dll_search_path, dll_name);

    /* Check if file exists */
    struct stat st;
    if (stat(path, &st) != 0) return -1;

    loaded_dll_t *dll = &reg->dlls[reg->count];
    strncpy(dll->name, dll_name, sizeof(dll->name) - 1);

    if (pe_load_image(path, &dll->image) != 0) {
        fprintf(stderr, "[DLL] Failed to load %s\n", path);
        return -1;
    }

    /* Resolve this DLL's own imports (it may depend on other DLLs) */
    if (dll->image.import_dir) {
        pe_resolve_imports(&dll->image, dll_registry_resolve, reg);
    }

    /* Skip DllMain for now - our shim DLLs don't need initialization.
     * Real ReactOS DLLs would need this, but it requires a fully
     * working kernel32 underneath first. */
    dll->initialized = 1;
    printf("[DLL] Skipping DllMain for %s (shim DLL)\n", dll_name);

    reg->count++;
    printf("[DLL] Loaded %s (%d exports available)\n", dll_name,
           dll->image.export_dir ? 1 : 0);  /* TODO: count exports */
    return 0;
}

int dll_registry_load_all(dll_registry_t *reg) {
    if (!reg->dll_search_path) return 0;

    DIR *dir = opendir(reg->dll_search_path);
    if (!dir) return 0;

    int loaded = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        size_t len = strlen(ent->d_name);
        if (len > 4 && dll_stricmp(ent->d_name + len - 4, ".dll") == 0) {
            if (dll_registry_load(reg, ent->d_name) == 0) {
                loaded++;
            }
        }
    }
    closedir(dir);
    return loaded;
}

void *dll_registry_resolve(const char *dll_name, const char *func_name,
                           uint16_t ordinal, void *ctx) {
    dll_registry_t *reg = (dll_registry_t*)ctx;
    if (!reg) reg = g_registry;
    if (!reg) return NULL;

    /* Strip path from dll_name if present */
    const char *base = dll_name;
    const char *p = dll_name;
    while (*p) {
        if (*p == '\\' || *p == '/') base = p + 1;
        p++;
    }

    /* Search loaded DLLs first */
    for (int i = 0; i < reg->count; i++) {
        if (dll_stricmp(reg->dlls[i].name, base) == 0) {
            /* Found the DLL - look up the export */
            if (func_name) {
                void *addr = pe_find_export(&reg->dlls[i].image, func_name);
                if (addr) return addr;
            }
            /* TODO: ordinal-based lookup */
        }
    }

    /* Fall back to stubs */
    if (reg->stub_resolver) {
        return reg->stub_resolver(dll_name, func_name, ordinal, reg->stub_ctx);
    }

    return NULL;
}

dll_registry_t *dll_registry_get(void) {
    return g_registry;
}
