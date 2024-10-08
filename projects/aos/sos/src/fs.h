#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>

#include "open_file.h"

#define FDT_SIZE 64

typedef struct {
    open_file **files;      // Array of pointers to open files
    uint64_t size;          // Maximum number of file descriptors
    uint64_t *free_list;    // Stack of free file descriptor indices
    uint64_t free_count;    // Number of free slots available
} fdt;

/**
 * Allocate memory for a per-process file descriptor table.
 * @param err Set to 0 if no error and set to 1 if calloc failed.
 * @return The value of the file descriptor table.
 */
fdt *fdt_create(char *err);

/**
 * Frees memory associated with a per-process file descriptor table.
 * @param fdt The value of the per-process file descriptor table.
 */
void fdt_destroy(fdt *fdt);

/**
 * Checks if the given file descriptor is valid or not.
 * @param fdt The value of the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return True if the given fd is valid and false otherwise.
 */
bool fdt_validfd(fdt *fdt, uint64_t fd);

/**
 * Returns a reference to the open file indexed by the given fd.
 * @param fdt The value of the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return A reference (pointer) to the open file.
 */
open_file *fdt_get_file(fdt *fdt, uint64_t fd);

/**
 * Puts the given file into the per-process fd table.
 * @param fdt The value of the per-process file descriptor table.
 * @param file The file you wish to add to the fd table.
 * @param fd A reference to the file descriptor the function will update.
 * @return 0 on success and 1 on failure.
 */
char fdt_put(fdt *fdt, open_file *file, uint64_t *fd);

/**
 * Removes a file with a given fd from the per-process fd table.
 * @param fdt The value of the per-process file descriptor table.
 * @param fd The file descriptor index into the fd table.
 * @return 0 on success and 1 on failure.
 */
int fdt_remove(fdt *fdt, uint64_t fd);