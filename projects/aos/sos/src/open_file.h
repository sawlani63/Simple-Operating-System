#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <sync/bin_sem.h>

typedef const char * string;
typedef int (*execute_io)(void *handle, char *data, uint64_t len, void *cb, void *args);

typedef struct file {
    void *handle; // i dont like this
    string path;
    int mode;
    execute_io file_write;
    execute_io file_read;
    sync_bin_sem_t *file_sem;
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