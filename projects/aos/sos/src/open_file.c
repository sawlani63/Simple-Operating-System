#include "open_file.h"

open_file *file_create(string path, int mode) {
    if (path == NULL) {
        return NULL;
    }
    open_file *file = malloc(sizeof(open_file));
    if (file == NULL) {
        return NULL;
    }
    file->mode = mode;
    file->path = path;
    file->nfsfh = NULL;
    return file;
}

void file_destroy(open_file *file) {
    /* Since the path address was provided to us by the user, we assume
     * either they explicitly free it, or it will be freed when the page
     * table gets cleared / swapped to disk. */
    free(file);
}

void nfsfh_init(open_file *file, void *nfsfh) {
    file->nfsfh = nfsfh;
}

int file_is_console(open_file *file) {
    return strcmp("console", file->path);
}