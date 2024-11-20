/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#pragma once

#include <sel4/types.h>
#include <cspace/cspace.h>
#include <sync/bin_sem.h>
#include <sys/time.h>
#include <nfsc/libnfs.h>
#include "open_file.h"

/**
 * Initialises the network stack
 *
 * @param cspace         for creating slots for mappings
 * @param ntfn_irq       badged notification object bound to SOS's endpoint, for ethernet IRQs
 * @param ntfn_tick      badged notification object bound to SOS's endpoint, for network tick IRQs
 * @param timer_vaddr    mapped timer device. network_init will set up a periodic network_tick
 *                       using the SoC's watchdog timer (which is not used by your timer driver
 *                       and has a completely different programming model!)
 */
void network_init(cspace_t *cspace, void *timer_vaddr, seL4_CPtr irq_ntfn, seL4_CPtr mount_signal);

void init_nfs_sem(void);

/* Thin wrappers around asynchronous libnfs functions.*/

/**
 * Wrapper around the asynchronous nfs open function. Waits for the callback to finish.
 * @param file pointer to the file we want to open
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return 0 on success
 */
int nfs_open_file(open_file *file, nfs_cb cb, void *private_data);

/**
 * Wrapper around the asynchronous nfs close function. Waits for the callback to finish.
 * @param file pointer to the file we want to close
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return 0 on success
 */
int nfs_close_file(open_file *file, nfs_cb cb, void *private_data);

/**
 * Wrapper around the asynchronous nfs pread function. Does not wait for the callback to finish.
 * @param file pointer to the file we want to read from
 * @param data unused parameter
 * @param offset the offset in the file to read from
 * @param count the number of bytes to read from the file
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return number of bytes told to read on success
 */
int nfs_pread_file(UNUSED int pid, open_file *file, UNUSED char *data, uint64_t offset, uint64_t count, void *cb, void *private_data);

int nfs_pwrite_handle(void *handle, char *buf, uint64_t offset, uint64_t count, void *cb, void *private_data);

/**
 * Wrapper around the asynchronous nfs pwrite function. Does not wait for the callback to finish.
 * @param file pointer to the file we want to write to
 * @param buf the buffer to write to the file
 * @param offset the offset to start writing from
 * @param count the number of bytes to write to the file
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return number of bytes told to write on success
 */
int nfs_pwrite_file(UNUSED int pid, open_file *file, char *buf, uint64_t offset, uint64_t count, void *cb, void *private_data);

/**
 * Wrapper around the asynchronous nfs stat function. Waits for the callback to finish.
 * @param path the name of the file to get information about
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return 0 on success
 */
int nfs_stat_file(const char *path, nfs_cb cb, void *private_data);

/**
 * Wrapper around the asynchronous nfs opendir function. Waits for the callback to finish
 * @param cb the callback to invoke when the task is complete
 * @param private_data our struct of i/o arguments to perform operations on them from the callback
 * 
 * @return 0 on success
 */
int nfs_open_dir(nfs_cb cb, void* private_data);

/**
 * Wrapper around the non-blocking nfs closedir function.
 * @param nfsdir pointer to the directory to close
 * 
 */
void nfs_close_dir(struct nfsdir *nfsdir);

/**
 * Wrapper around the non-blocking nfs readdir function.
 * @param nfsdir pointer to the directory to read from
 * 
 * @return list of directory entries on success
 */
struct nfsdirent *nfs_read_dir(struct nfsdir *nfsdir);