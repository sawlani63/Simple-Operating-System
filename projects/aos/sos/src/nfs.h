#ifndef NFS
#define NFS

#include <stdlib.h>
#include <sync/bin_sem.h>

#include "fs.h"
#include "network.h"

#define ST_FILE    1    /* plain file */
#define ST_SPECIAL 2    /* special (console) file */

typedef struct {
    int       st_type;    /* file type */
    int       st_fmode;   /* access mode */
    unsigned  st_size;    /* file size in bytes */
    long      st_ctime;   /* Unix file creation time (ms) */
    long      st_atime;   /* Unix file last access (open) time (ms) */
} sos_stat_t;

typedef struct nfs_args {
    int err;
    void *buff;
    sync_bin_sem_t *sem;
} nfs_args;

void nfs_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in closing file, %s\n", (char*) data);
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_stat_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    } else {
        struct nfs_stat_64 *stat = (struct nfs_stat_64 *) data;
        sos_stat_t *sos_stat = (sos_stat_t *) args->buff;
        
        sos_stat->st_type = ST_FILE;
        sos_stat->st_fmode = stat->nfs_mode;
        sos_stat->st_size = stat->nfs_size;
        sos_stat->st_atime = stat->nfs_atime;
        sos_stat->st_ctime = stat->nfs_ctime;
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_lseek_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data)
{
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in seeking read pointer, %s\n", (char*) data);
    } else {
        // update offset
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

#endif