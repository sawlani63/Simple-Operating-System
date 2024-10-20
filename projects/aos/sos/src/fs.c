#include "fs.h"

/* Simple realloc up helper function. Returns 0 for sucess, 1 for failure. */
static int fdt_grow(fdt *fdt) {
    fdt->files = realloc(fdt->files, fdt->size * 2 * sizeof(open_file *));
    fdt->free_list = realloc(fdt->free_list, fdt->size * 2 * sizeof(uint32_t));
    if (fdt->files && fdt->free_list) {
        // Populate the new free slots in free_list
        for (uint32_t fd = fdt->size; fd < fdt->size * 2; fd++) {
            fdt->free_list[fdt->free_count++] = fd;
        }
        fdt->size *= 2;
        return 0;
    }
    return 1;
}

/* Simple realloc down helper function. Returns 0 for sucess, 1 for failure. */
static int fdt_try_shrink(fdt *fdt) {
    // Set a threshold to be 25% of the current size
    if (fdt->size > FDT_SIZE && fdt->free_count >= (3 * fdt->size / 4)) {
        fdt->files = realloc(fdt->files, (fdt->size / 2) * sizeof(open_file *));
        fdt->free_list = realloc(fdt->free_list, (fdt->size / 2) * sizeof(uint32_t));

        if (fdt->files && fdt->free_list) {
            fdt->size /= 2;
            fdt->free_count = 3 * fdt->size / 4;
            return 0;
        }
        return 1;
    }
    return 0;
}

fdt *fdt_create(char *err) {
    fdt *new = malloc(sizeof(fdt));
    new->files = calloc(sizeof(open_file *), FDT_SIZE);
    new->free_list = malloc(sizeof(uint32_t) * FDT_SIZE);

    if (new->files == NULL || new->free_list == NULL) {
        *err = 1;
        free(new->files);
        free(new->free_list);
        free(new);
    } else {
        *err = 0;
        new->size = FDT_SIZE;
        new->free_count = FDT_SIZE;
        /* Save fd = 0 for stdout. */
        for (uint32_t fd = 1; fd < FDT_SIZE; fd++) {
            new->free_list[FDT_SIZE - fd] = fd;
        }
    }
    return new;
}

void fdt_destroy(fdt *fdt) {
    for (uint32_t i = 0; i < fdt->size; i++) {
        file_destroy(fdt->files[i]);
    }
    free(fdt->files);
    free(fdt->free_list);
    free(fdt);
}

inline bool fdt_validfd(fdt *fdt, uint32_t fd) {
    return fd < fdt->size - 1;
}

inline open_file *fdt_get_file(fdt *fdt, uint32_t fd) {
    return !fdt_validfd(fdt, fd) ? NULL : fdt->files[fd];
}

int fdt_put(fdt *fdt, open_file *file, uint32_t *fd) {
    if (!fdt->free_count && fdt_grow(fdt)) {
        return 1;
    }

    *fd = fdt->free_list[--fdt->free_count];
    fdt->files[*fd] = file;
    return 0;
}

int fdt_remove(fdt *fdt, uint32_t fd) {
    if (!fdt_validfd(fdt, fd)) {
        return 1;
    }
    file_destroy(fdt->files[fd]);
    fdt->files[fd] = NULL;
    fdt->free_list[fdt->free_count++] = fd;
    return fdt_try_shrink(fdt);
}