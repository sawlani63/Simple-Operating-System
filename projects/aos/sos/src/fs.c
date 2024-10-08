#include "fs.h"

fdt *fdt_create(char *err) {
    fdt *fdt_ptr = malloc(sizeof(fdt));
    /* Use a normal fdt for now which we will set the fdt_ptr
     * to later, to avoid lots of pointer dereferencing. */
    fdt fdt = {.size = FDT_SIZE, .free_count = FDT_SIZE};

    fdt.files = calloc(sizeof(open_file *), FDT_SIZE);
    fdt.free_list = malloc(sizeof(uint64_t) * FDT_SIZE);

    if (fdt.files == NULL || fdt.free_list == NULL) {
        *err = 1;
    } else {
        *err = 0;
        /* Save fd = 0 for stdout. */
        for (uint64_t fd = 1; fd < FDT_SIZE; fd++) {
            fdt.free_list[FDT_SIZE - fd] = fd;
        }
    }

    *fdt_ptr = fdt;
    return fdt_ptr;
}   

void fdt_destroy(fdt *fdt_ptr) {
    if (fdt_ptr == NULL) {
        return;
    }

    // Cache the fdt_ptr to avoid lots of pointer dereferencing
    fdt fdt = *fdt_ptr;
    for (uint64_t i = 0; i < fdt.size; i++) {
        file_destroy(fdt.files[i]);
    }
    free(fdt.files);
    free(fdt.free_list);
    free(fdt_ptr);
}

bool fdt_validfd(fdt fdt, uint64_t fd) {
    return fd < fdt.size - 1;
}

open_file *fdt_get_file(fdt fdt, uint64_t fd) {
    return !fdt_validfd(fdt, fd) ? NULL : fdt.files[fd];
}

char fdt_put(fdt *fdt_ptr, open_file *file, uint64_t *fd) {
    // Cache the fdt_ptr to avoid lots of pointer dereferencing
    fdt fdt = *fdt_ptr;
    if (fdt.free_count == 0) {
        return 1;
    }

    uint64_t cache_fd = *fd = fdt.free_list[--fdt.free_count];
    fdt.files[cache_fd] = file;
    *fdt_ptr = fdt;
    return 0;
}

int fdt_remove(fdt *fdt_ptr, uint64_t fd) {
    // Cache the fdt_ptr to avoid lots of pointer dereferencing
    fdt fdt = *fdt_ptr;
    if (!fdt_validfd(fdt, fd)) {
        return 1;
    }
    file_destroy(fdt.files[fd]);
    fdt.files[fd] = NULL;
    fdt.free_list[fdt.free_count++] = fd;
    *fdt_ptr = fdt;
    return 0;
}