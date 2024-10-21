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
#include <autoconf.h>
#include <utils/util.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <errno.h>
#include <assert.h>
#include <sos.h>

/*
 * Statically allocated morecore area.
 *
 * This is rather terrible, but is the simplest option without a
 * huge amount of infrastructure.
 */
#define MORECORE_AREA_BYTE_SIZE 0x100000
char morecore_area[MORECORE_AREA_BYTE_SIZE];

/* Pointer to free space in the morecore area. */
static uintptr_t morecore_base = (uintptr_t) &morecore_area;
static uintptr_t morecore_top = (uintptr_t) &morecore_area[MORECORE_AREA_BYTE_SIZE];

/* Actual morecore implementation
   returns 0 if failure, returns newbrk if success.
*/

long sys_brk(va_list ap)
{
    seL4_SetMR(0, SYS_brk);
    seL4_SetMR(1, va_arg(ap, uintptr_t));
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
    return seL4_GetMR(0);
}

/* Large mallocs will result in muslc calling mmap, so we do a minimal implementation
   here to support that. We make a bunch of assumptions in the process */
long sys_mmap(va_list ap)
{
    void *addr = va_arg(ap, void *);
    size_t length = va_arg(ap, size_t);
    int prot = va_arg(ap, int);
    int flags = va_arg(ap, int);
    int fd = va_arg(ap, int);
    off_t offset = va_arg(ap, off_t);

    if (flags & MAP_ANONYMOUS) {
        seL4_SetMR(0, SYS_mmap);
        seL4_SetMR(1, (seL4_Word) addr);
        seL4_SetMR(2, length);
        seL4_SetMR(3, prot);
        seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
        return seL4_GetMR(0);
    }
    ZF_LOGF("not implemented");
    return -ENOMEM;
}

/* Large frees will result in muslc calling munmap, so we do a minimal implementation
   here to support that. We make a bunch of assumptions in the process */
long sys_munmap(va_list ap)
{
    void *start = va_arg(ap, void *);
    size_t len = va_arg(ap, size_t);
    
    seL4_SetMR(0, SYS_munmap);
    seL4_SetMR(1, (seL4_Word) start);
    seL4_SetMR(2, len);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 3));
    return seL4_GetMR(0);
}
