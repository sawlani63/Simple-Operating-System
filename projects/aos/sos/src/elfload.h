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

#include <sel4/sel4.h>
#include <cspace/cspace.h>
#include <elf/elf.h>
#include <elf.h>
#include "sos_syscall.h"

int elf_load(cspace_t *cspace, elf_t *elf_file, open_file *file, addrspace_t *as, seL4_CPtr vspace, unsigned *size, pid_t pid, bool timer);
char *elf_load_header(open_file *file, unsigned long *elf_size);