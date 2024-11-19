#pragma once

#include "network.h"
#include "fs.h"

#define ST_FILE    1    /* plain file */
#define ST_SPECIAL 2    /* special (console) file */

typedef struct {
    int       st_type;    /* file type */
    int       st_fmode;   /* access mode */
    unsigned  st_size;    /* file size in bytes */
    long      st_ctime;   /* Unix file creation time (ms) */
    long      st_atime;   /* Unix file last access (open) time (ms) */
} sos_stat_t;

/* Callbacks invoked after asynchronous nfs operations. They signal the thread waiting for the 
   callback to finish and copy any required data to our i/o struct of arguments (private_data). */
void nfs_async_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_async_close_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_buffercache_read_rdcb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_buffercache_read_wrcb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_buffercache_flush_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_async_stat_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_async_opendir_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

/* Callbacks invoked specifically for pagefile related operations.*/
void nfs_pagefile_read_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);
void nfs_pagefile_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);