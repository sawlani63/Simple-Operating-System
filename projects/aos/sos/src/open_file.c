#include "open_file.h"

open_file *file_create(string path, int mode, wr_handler file_write, rd_handler file_read) {
    if (path == NULL || file_write == NULL || file_read == NULL) {
        return NULL;
    }
    open_file *file = malloc(sizeof(open_file));
    if (file == NULL) {
        return NULL;
    }
    file->mode = mode;
    file->path = path;
    file->offset = 0;
    file->file_read = file_read;
    file->file_write = file_write;
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