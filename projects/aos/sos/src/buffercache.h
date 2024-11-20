#pragma once

#include <stdint.h>
#include "fs.h"

typedef struct buffer_cache_args {
    void *handle;
    uint64_t offset;
    char *data;
    uint16_t len;
} buffer_cache_args_t;

typedef struct cache_key {
    void *handle;
    uint64_t block_num;
} cache_key_t;

int buffercache_init();

int buffercache_write(int pid, struct file *file, char *data, uint64_t offset, uint64_t len, void *cb, void *args);

int buffercache_read(int pid, struct file *file, char *data, uint64_t offset, uint64_t len, void *cb, void *args);

int buffercache_flush(open_file *file);

int buffercache_clean_frame(cache_key_t key, frame_ref_t ref);