#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <sync/bin_sem.h>

#define LEVEL_SIZE 32

typedef const char * string;
struct file;

typedef const char * string;
typedef int (*execute_io)(struct file *file, char *data, uint64_t offset, uint64_t len, void *cb, void *args);

typedef struct file {
    // File metadata
    void *handle;
    string path;
    int mode;
    size_t offset;
    size_t size;

    // File operations
    execute_io file_write;
    execute_io file_read;
    sync_bin_sem_t *file_sem;

    /* A three-level bitmap describing the indices that the file is using in the buffer cache map. This
     * is a compact structure for memory efficiency since it is stored in every file. Each level stores
     * 2^5 = 32 entries, with each file incurring a static 256 byte cost for storing the top level. */
    uint8_t **cache_blocks[LEVEL_SIZE];
} open_file;

/**
 * Allocate memory and return a pointer to a new open file.
 * @param path A string containing the path to the file.
 * @param mode The permissions of the file (O_RDONLY, O_WRONLY, O_RDWR).
 * @param file_write A function pointer used as the write callback.
 * @param file_read A function pointer used as the read callback.
 * @return The value of the file open file.
 */
open_file *file_create(string path, int mode, execute_io file_write, execute_io file_read);

/**
 * Deallocates memory for the given file.
 * @param file A reference to an open file to be deallocated.
 */
void file_destroy(open_file *file);

int mark_block_dirty(open_file *file, uint32_t cache_block);

int mark_block_clean(open_file *file, uint32_t cache_block);

void cleanup_bitmap(open_file *file);