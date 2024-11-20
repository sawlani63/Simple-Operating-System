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

#include <sel4runtime.h>
#include "ut.h"
#include <sync/bin_sem.h>

extern cspace_t cspace;
extern sync_bin_sem_t *cspace_sem;

/* helper to allocate a ut + cslot, and retype the ut into the cslot */
ut_t *alloc_retype(seL4_CPtr *cptr, seL4_Word type, size_t size_bits);
/* helper to delete a capability, free the cslot and mark the untyped memory as free */
void free_untype(seL4_CPtr *cptr, ut_t *node);
