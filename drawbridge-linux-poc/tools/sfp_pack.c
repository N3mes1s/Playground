/*
 * SFP Packer - Creates .sfp archives for SQLPAL
 *
 * Usage: sfp_pack <output.sfp> <input_directory>
 *
 * Creates an SFP archive from a directory, matching the format
 * that the SQLPAL host expects.
 */

#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <time.h>

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;       /* 0x5346504B = "SFPK" */
    uint32_t version;     /* 2 */
    uint64_t unk1;        /* 0 */
    uint64_t firstDirOffset;
    uint64_t nameTableOffset;
    uint64_t dataOffset;
    uint64_t archiveSize;
    uint64_t packageLabelOffset;
    uint64_t unk3;        /* 0 */
} sfp_header;

typedef struct {
    uint32_t magic;       /* 0x5346504B = "SFPK" */
    uint64_t nameOffset;
    uint32_t unk1;        /* 0 */
    uint64_t parentOffset;
    uint32_t isDir;
    uint64_t fileLength;
    uint64_t modifiedTime;
    uint64_t createdTime;
    uint64_t unk2;        /* 0 */
    uint64_t unk3;        /* 0 */
    uint64_t startOffset;
    uint32_t dataLength;
} __attribute__((packed)) sfp_dir_entry;

#pragma pack(pop)

/* Name table builder */
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} name_table_t;

static void nt_init(name_table_t *nt) {
    nt->cap = 4096;
    nt->data = malloc(nt->cap);
    nt->len = 0;
}

static uint64_t nt_add(name_table_t *nt, const char *name) {
    size_t slen = strlen(name) + 1;
    /* Encode as UTF-16LE */
    size_t wlen = slen * 2;
    while (nt->len + wlen > nt->cap) {
        nt->cap *= 2;
        nt->data = realloc(nt->data, nt->cap);
    }
    uint64_t offset = nt->len;
    for (size_t i = 0; i < slen; i++) {
        nt->data[nt->len++] = name[i];
        nt->data[nt->len++] = 0;  /* UTF-16LE high byte */
    }
    return offset;
}

/* File entry collector */
typedef struct file_entry {
    char path[512];         /* Full path on disk */
    char relpath[512];      /* Relative path in archive */
    int is_dir;
    size_t size;
    uint64_t name_offset;   /* Offset in name table */
    uint64_t parent_dir_offset; /* Offset of parent dir entry */
    uint64_t dir_entry_offset;  /* This entry's offset in the dir table */
    uint64_t data_offset;   /* For files: offset in data section */
} file_entry_t;

static file_entry_t entries[4096];
static int num_entries = 0;

static void collect_files(const char *base_dir, const char *rel_prefix,
                          name_table_t *nt, uint64_t parent_offset) {
    DIR *d = opendir(base_dir);
    if (!d) return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        file_entry_t *e = &entries[num_entries];
        snprintf(e->path, sizeof(e->path), "%s/%s", base_dir, ent->d_name);
        snprintf(e->relpath, sizeof(e->relpath), "%s%s", rel_prefix, ent->d_name);

        struct stat st;
        if (stat(e->path, &st) != 0) continue;

        e->is_dir = S_ISDIR(st.st_mode);
        e->size = e->is_dir ? 0 : st.st_size;
        e->name_offset = nt_add(nt, ent->d_name);
        e->parent_dir_offset = parent_offset;
        e->dir_entry_offset = 0;  /* Set later */
        e->data_offset = 0;

        num_entries++;

        if (e->is_dir) {
            char subdir[1024];
            char subrel[1024];
            snprintf(subdir, sizeof(subdir), "%s/%s", base_dir, ent->d_name);
            snprintf(subrel, sizeof(subrel), "%s%s/", rel_prefix, ent->d_name);
            collect_files(subdir, subrel, nt, 0 /* updated later */);
        }
    }
    closedir(d);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <output.sfp> <input_directory>\n", argv[0]);
        return 1;
    }

    const char *output_path = argv[1];
    const char *input_dir = argv[2];

    printf("[SFP] Packing %s -> %s\n", input_dir, output_path);

    /* Build name table and collect file entries */
    name_table_t nt;
    nt_init(&nt);

    /* Add the root directory name (the package label) */
    /* Extract just the directory name */
    const char *pkg_name = strrchr(input_dir, '/');
    pkg_name = pkg_name ? pkg_name + 1 : input_dir;
    /* Strip .sfp extension if present */
    char label[256];
    strncpy(label, pkg_name, sizeof(label));
    char *dot = strstr(label, ".sfp");
    if (dot) *dot = 0;

    uint64_t root_name = nt_add(&nt, label);

    /* Create root entry */
    file_entry_t *root = &entries[0];
    strncpy(root->path, input_dir, sizeof(root->path));
    strncpy(root->relpath, "", sizeof(root->relpath));
    root->is_dir = 1;
    root->size = 0;
    root->name_offset = root_name;
    root->parent_dir_offset = 0;
    num_entries = 1;

    /* Collect all files recursively */
    collect_files(input_dir, "", &nt, 0);

    printf("[SFP] Collected %d entries\n", num_entries);

    /* Calculate layout:
     * [header] [dir entries] [name table] [file data]
     */
    uint64_t header_size = sizeof(sfp_header);
    uint64_t dir_size = (uint64_t)num_entries * sizeof(sfp_dir_entry);
    uint64_t dir_offset = header_size;
    uint64_t name_offset = dir_offset + dir_size;
    uint64_t data_offset = name_offset + nt.len;

    /* Align data to 16 bytes */
    data_offset = (data_offset + 15) & ~15ULL;

    /* Assign dir entry offsets */
    for (int i = 0; i < num_entries; i++) {
        entries[i].dir_entry_offset = dir_offset + (uint64_t)i * sizeof(sfp_dir_entry);
    }

    /* Assign data offsets for files */
    uint64_t current_data = data_offset;
    for (int i = 0; i < num_entries; i++) {
        if (!entries[i].is_dir && entries[i].size > 0) {
            entries[i].data_offset = current_data;
            current_data += entries[i].size;
            current_data = (current_data + 15) & ~15ULL;
        }
    }

    /* For directories: set startOffset and dataLength to point to child entries */
    for (int i = 0; i < num_entries; i++) {
        if (entries[i].is_dir) {
            /* Find children of this directory */
            /* Simple: children are entries whose parent path matches */
            /* For now, root's children are all top-level entries */
            uint64_t first_child = 0;
            uint32_t child_count = 0;
            for (int j = 1; j < num_entries; j++) {
                /* Check if j's parent is i */
                /* Simple heuristic: depth-based */
                if (i == 0) {
                    /* Root's children: entries at depth 1 */
                    if (strchr(entries[j].relpath, '/') == NULL ||
                        (strchr(entries[j].relpath, '/') == entries[j].relpath + strlen(entries[j].relpath) - 1)) {
                        if (first_child == 0) first_child = entries[j].dir_entry_offset;
                        child_count++;
                    }
                }
            }
            entries[i].data_offset = first_child;
            entries[i].size = child_count * sizeof(sfp_dir_entry);
        }
    }

    uint64_t archive_size = current_data;

    /* Write the archive */
    FILE *f = fopen(output_path, "wb");
    if (!f) { perror("Cannot create output"); return 1; }

    /* Header */
    sfp_header hdr = {0};
    hdr.magic = 0x4B504653;  /* "SFPK" */
    hdr.version = 2;
    hdr.firstDirOffset = dir_offset;
    hdr.nameTableOffset = name_offset;
    hdr.dataOffset = data_offset;
    hdr.archiveSize = archive_size;
    hdr.packageLabelOffset = root_name;
    fwrite(&hdr, 1, sizeof(hdr), f);

    /* Directory entries */
    for (int i = 0; i < num_entries; i++) {
        sfp_dir_entry de = {0};
        de.magic = 0x4B504653;
        de.nameOffset = entries[i].name_offset;
        de.parentOffset = entries[i].parent_dir_offset;
        de.isDir = entries[i].is_dir;
        de.fileLength = entries[i].size;
        de.modifiedTime = time(NULL);
        de.createdTime = de.modifiedTime;
        de.startOffset = entries[i].data_offset;
        de.dataLength = (uint32_t)entries[i].size;
        fwrite(&de, 1, sizeof(de), f);
    }

    /* Name table */
    fwrite(nt.data, 1, nt.len, f);

    /* Pad to data offset */
    while ((uint64_t)ftello(f) < data_offset) fputc(0, f);

    /* File data */
    for (int i = 0; i < num_entries; i++) {
        if (!entries[i].is_dir && entries[i].size > 0) {
            while ((uint64_t)ftello(f) < entries[i].data_offset) fputc(0, f);
            FILE *src = fopen(entries[i].path, "rb");
            if (src) {
                char buf[8192];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), src)) > 0) fwrite(buf, 1, n, f);
                fclose(src);
            }
        }
    }

    fclose(f);
    printf("[SFP] Created %s (%lu bytes, %d entries)\n",
           output_path, (unsigned long)archive_size, num_entries);

    free(nt.data);
    return 0;
}
