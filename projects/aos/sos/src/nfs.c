#include "nfs.h"
#include <stdlib.h>
#include <sync/bin_sem.h>

void nfs_async_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_async_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in closing file, %s\n", (char*) data);
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}

void nfs_async_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file, %s\n", (char*) data);
    } else {
        memcpy(args->buff, data, args->err);
    }
    seL4_SetMR(0, args->err);
    seL4_SetMR(1, err);
    seL4_Send(args->io_ep, seL4_MessageInfo_new(0, 0, 0, 2));
}

void nfs_async_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    }
    seL4_SetMR(0, args->err);
    seL4_SetMR(1, err);
    seL4_Send(args->io_ep, seL4_MessageInfo_new(0, 0, 0, 2));

}

void nfs_async_stat_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
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

void nfs_async_opendir_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening dir, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    sync_bin_sem_post(args->sem);
}