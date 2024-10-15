#include "open_file.h"
#include "ut.h"
#include "utils.h"

open_file *file_create(string path, int mode, execute_io file_write, execute_io file_read) {
    if (path == NULL || file_write == NULL || file_read == NULL) {
        return NULL;
    }
    open_file *file = malloc(sizeof(open_file));
    if (file == NULL) {
        return NULL;
    }
    file->handle = NULL;
    file->mode = mode;
    file->path = path;
    file->file_read = file_read;
    file->file_write = file_write;
    file->file_sem = malloc(sizeof(sync_bin_sem_t));

    ZF_LOGF_IF(!file->file_sem, "No memory for semaphore object");
    seL4_CPtr cptr;
    ut_t *sem_ut = alloc_retype(&cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(file->file_sem, cptr, 1);
    
    return file;
}

void file_destroy(open_file *file) {
    /* Since the path address was provided to us by the user, we assume
     * either they explicitly free it, or it will be freed when the page
     * table gets cleared / swapped to disk. */
    free(file->file_sem);
    free(file);
}