#include <stdlib.h>
#include <sync/bin_sem.h>

#include "nfs.h"
#include "sos_syscall.h"
#include "frame_table.h"

extern sync_bin_sem_t *data_sem;

void nfs_async_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    seL4_Signal(args->signal_cap);
}

void nfs_async_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in closing file, %s\n", (char*) data);
    }
    args->err = err;
    seL4_Signal(args->signal_cap);
}

void nfs_buffercache_read_rdcb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file with rdcb, %s\n", (char*) data);
    } else {
        sync_bin_sem_wait(data_sem);
        memcpy(args->buff, data, err);
        if (args->num_frames > 0) {
            for (int i = 0; i < args->num_frames; i++) {
                memcpy(frame_data(args->cache_frames[i]), data, NFS_BLKSIZE);
            }
            err = args->err;
            free(args->cache_frames);
        }
        unpin_frame(args->entry->page.frame_ref);
        sync_bin_sem_post(data_sem);
    }
    seL4_SetMR(0, args->err);
    seL4_SetMR(1, err);
    seL4_Send(args->signal_cap, seL4_MessageInfo_new(0, 0, 0, 2));
    free(args);
}

void nfs_buffercache_read_wrcb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file with wrcb, %s\n", (char*) data);
    } else {
        sync_bin_sem_wait(data_sem);
        if (*(args->cache_frames) != NULL_FRAME) {
            memcpy(frame_data(*(args->cache_frames)), args->buff, args->err);
            err = args->err;
        }
        unpin_frame(args->entry->page.frame_ref);
        sync_bin_sem_post(data_sem);
    }
    seL4_SetMR(0, args->err);
    seL4_SetMR(1, err);
    seL4_Send(args->signal_cap, seL4_MessageInfo_new(0, 0, 0, 2));
    free(args);
}

void nfs_buffercache_flush_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in flushing file, %s\n", (char*) data);
    }
    seL4_SetMR(0, args->err);
    seL4_SetMR(1, args->err);
    seL4_Send(args->signal_cap, seL4_MessageInfo_new(0, 0, 0, 2));
    free(args);
}

void nfs_pagefile_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file, %s\n", (char*) data);
    } else {
        memcpy(args->buff, data, err);
    }
    args->err = err;
    seL4_Signal(args->signal_cap);
}

void nfs_pagefile_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    }
    args->err = err;
    seL4_Signal(args->signal_cap);
}

void nfs_async_stat_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in getting stats of file, %s\n", (char*) data);
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
    seL4_Signal(args->signal_cap);
}

void nfs_async_opendir_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    io_args *args = (io_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening dir, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
    seL4_Signal(args->signal_cap);
}