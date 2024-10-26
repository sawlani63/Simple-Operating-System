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
void network_init(cspace_t *cspace, void *timer_vaddr, seL4_CPtr irq_ntfn);

void init_nfs_sem(void);

int nfs_open_file(const char* path, int mode, nfs_cb cb, void *private_data);
int nfs_close_file(void *nfsfh, nfs_cb cb, void *private_data);
int nfs_pread_file(open_file *file, UNUSED char *data, uint64_t offset, uint64_t count, void *cb, void *private_data);
int nfs_read_file(open_file *file, UNUSED char *data, uint64_t offset, uint64_t count, void *cb, void *private_data);
int nfs_pwrite_file(open_file *file, char *buf, uint64_t offset, uint64_t count, void *cb, void *private_data);
int nfs_write_file(open_file *file, char *buf, uint64_t offset, uint64_t count, void *cb, void *private_data);
int nfs_stat_file(const char *path, nfs_cb cb, void *private_data);
int nfs_open_dir(nfs_cb cb, void* private_data);
void nfs_close_dir(struct nfsdir *nfsdir);
struct nfsdirent *nfs_read_dir(struct nfsdir *nfsdir);