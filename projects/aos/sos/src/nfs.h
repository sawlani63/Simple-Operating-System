#pragma once

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
    seL4_CPtr io_ep;
} nfs_args;

void nfs_async_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

void nfs_async_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

void nfs_async_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

void nfs_async_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

void nfs_async_stat_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

void nfs_async_opendir_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);


void nfs_pagefile_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_pagefile_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);