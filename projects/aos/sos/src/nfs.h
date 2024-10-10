#include <stdlib.h>
#include <sync/bin_sem.h>

#include "fs.h"
#include "network.h"

typedef struct nfs_args {
    int err;
    void *buff;
} nfs_args;

void nfs_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in opening file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
}

void nfs_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err) {
        ZF_LOGE("NFS: Error in closing file, %s\n", (char*) data);
    }
    args->err = err;
}

void nfs_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file, %s\n", (char*) data);
    } else {
        args->buff = data;
    }
    args->err = err;
}

void nfs_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data) {
    nfs_args *args = (nfs_args *) private_data;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    }
    args->err = err;
}