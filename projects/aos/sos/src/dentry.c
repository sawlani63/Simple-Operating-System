#include "dentry.h"
#include "khash.h"
#include "network.h"
#include "nfs.h"

#define DENTRY_CACHE_SIZE 256 // Dentry cache is as big as the amount of files we can have (256 with 16 process)
khiter_t unused_file_queue[DENTRY_CACHE_SIZE];
uint8_t head = 0;
uint8_t tail = 0;

typedef struct dentry_value {
    void *handle;
    size_t size;
    size_t references;
} dentry_value_t;

KHASH_MAP_INIT_STR(dentry, dentry_value_t)

khash_t(dentry) *dentry_map = NULL;

/* Initialise a dentry cache map.
 * This should take up 16B (flags) + 8KB (keys) + 8KB (values) ≈ 16KB of space */
int dentry_init() {
    dentry_map = kh_init(dentry);
    if (dentry_map == NULL) {
        return 1;
    }
    return kh_resize(dentry, dentry_map, DENTRY_CACHE_SIZE) < 0 ? 1 : 0;
}

open_file *dentry_check(string path, int mode, execute_io file_write, execute_io file_read) {
    open_file *file = file_create(path, mode, file_write, file_read);
    khiter_t iter = kh_get(dentry, dentry_map, path);
    if (iter != kh_end(dentry_map)) {
        dentry_value_t entry = kh_value(dentry_map, iter);
        file->handle = entry.handle;
        file->size = entry.size;
        kh_value(dentry_map, iter).references++;
    }
    return file;
}

extern seL4_CPtr nfs_signal;
static inline void dentry_remove_first() {
    khiter_t iter = unused_file_queue[head];
    head = (head + 1) % DENTRY_CACHE_SIZE;
    io_args args = {.signal_cap = nfs_signal};
    if (nfs_close_file(kh_value(dentry_map, iter).handle, nfs_async_close_cb, &args) < 0) {
        seL4_SetMR(0, -1);
        return;
    }
    if (args.err) {
        seL4_SetMR(0, -1);
        return;
    }
    kh_del(dentry, dentry_map, iter);
}

int dentry_write(open_file *file) {
    int err;
    khiter_t iter = kh_put(dentry, dentry_map, file->path, &err);
    if (err == -1) {
        dentry_remove_first();
    }
    iter = kh_put(dentry, dentry_map, file->path, &err);
    if (err == -1) {
        printf("Unexpected error when writing to dentry\n");
        return -1;
    }
    kh_value(dentry_map, iter) = (dentry_value_t){file->handle, file->size, 1};
    return 0;
}

void dentry_mark_closed(open_file *file) {
    khiter_t iter = kh_get(dentry, dentry_map, file->path);
    kh_value(dentry_map, iter).size = file->size;
    size_t references = --kh_value(dentry_map, iter).references;
    if (!references) {
        unused_file_queue[tail] = iter;
        tail = (tail + 1) % DENTRY_CACHE_SIZE;
    }
}