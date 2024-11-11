#include "fs.h"

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
        /* Save fd = 0 for stdin. */
        for (uint32_t fd = 1; fd < FDT_SIZE; fd++) {
            new->free_list[FDT_SIZE - fd] = fd;
        }
    }
    return new;
}

void fdt_destroy(fdt *fdt) {
    for (uint32_t i = 0; i < fdt->size; i++) {
        if (i == 2) {
            continue;
        } //better way for this
        file_destroy(fdt->files[i]);
    }
    free(fdt->files);
    free(fdt->free_list);
    free(fdt);
}

void fdt_put_console(fdt *fdt, open_file *file, uint32_t *fd) {
    *fd = 0;
    fdt->files[0] = file;
}

int fdt_put(fdt *fdt, open_file *file, uint32_t *fd) {
    if (!fdt->free_count) {
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
    if (fd != 0) {
        fdt->free_list[fdt->free_count++] = fd;
    }
    return 0;
}