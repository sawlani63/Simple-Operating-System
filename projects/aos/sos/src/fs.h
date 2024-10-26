#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "open_file.h"

#define FDT_SIZE 16         // Starting size of the fd table

/* Per-process file descriptor table data structure. */
typedef struct {
    open_file **files;      // Array of pointers to open files
    uint32_t size;          // Maximum number of file descriptors
    uint32_t *free_list;    // Stack of free file descriptor indices
    uint32_t free_count;    // Number of free slots available
} fdt;

/**
 * Allocate memory for a per-process file descriptor table.
 * @param err Set to 0 if no error and set to 1 if calloc failed.
 * @return A pointer to the file descriptor table.
 */
fdt *fdt_create(char *err);

/**
 * Frees memory associated with a per-process file descriptor table.
 * @param fdt A pointer to the per-process file descriptor table.
 */
void fdt_destroy(fdt *fdt);

/**
 * Checks if the given file descriptor is valid or not.
 * @param fdt A pointer to the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return True if the given fd is valid and false otherwise.
 */
static inline bool fdt_validfd(fdt *fdt, uint32_t fd) {
    return fd < fdt->size - 1;
}

/**
 * Returns a reference to the open file indexed by the given fd.
 * @param fdt A pointer to the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return A reference (pointer) to the open file.
 */
static inline open_file *fdt_get_file(fdt *fdt, uint32_t fd) {
    return !fdt_validfd(fdt, fd) ? NULL : fdt->files[fd];
}

/**
 * Puts the given file into the per-process fd table.
 * @param fdt A pointer to the per-process file descriptor table.
 * @param file The file you wish to add to the fd table.
 * @param fd A reference to the file descriptor the function will update.
 * @return 0 on success and 1 on failure.
 */
int fdt_put(fdt *fdt, open_file *file, uint32_t *fd);

/**
 * Removes a file with a given fd from the per-process fd table.
 * @param fdt A pointer to the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return 0 on success and 1 on failure.
 */
int fdt_remove(fdt *fdt, uint32_t fd);