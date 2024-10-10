#ifndef ADDRSPACE
#define ADDRSPACE

#include <cspace/cspace.h>
#include "frame_table.h"

#define PAGE_TABLE_ENTRIES 0b1 << seL4_VSpaceIndexBits

#define REGION_RD 0x1u
#define REGION_WR 0x2u
#define REGION_EX 0x4u

typedef struct _region {
    seL4_Word base;
    size_t size;
    unsigned char perms;
    struct _region *next;
} mem_region_t;

/* Packs the entire entry into 64 bits.
 * The lowest 19 bits contain the frame reference,
 * the next 12 bits contain the frame cap to the hpt,
 * and the next 3 bits contain the permissions.
 * The last 30 bits remain unused.*/
typedef uint64_t pt_entry;

typedef struct pt_l3 {
    pt_entry *l4;
    seL4_CPtr slot;
    ut_t *ut;
} page_table;

typedef struct pt_l2 {
    page_table *l3;
    seL4_CPtr slot;
    ut_t *ut;
} page_directory;

typedef struct pt_l1 {
    page_directory *l2;
    seL4_CPtr slot;
    ut_t *ut;
} page_upper_directory;

typedef struct addrspace {
    page_upper_directory *page_table;
    mem_region_t *regions;
} addrspace_t;

/*
 * Functions in addrspace.c:
 *
 *    as_create - create a new empty address space. You need to make
 *                sure this gets called in all the right places. You
 *                may find you want to change the argument list. May
 *                return NULL on out-of-memory error.
 *
 *    as_define_region - set up a region of memory within the address
 *                space.
 *
 *    as_define_stack - set up the stack region in the address space.
 *                Hands back the initial stack pointer for the new process.
 *
 * Note that when using dumbvm, addrspace.c is not used and these
 * functions are found in dumbvm.c.
 */

addrspace_t *as_create();
mem_region_t *as_define_region(addrspace_t *as, seL4_Word vaddr, size_t memsize, unsigned char perms);
mem_region_t *as_define_ipc_buff(addrspace_t *as, seL4_Word *initipcbuff);
mem_region_t *as_define_stack(addrspace_t *as);
mem_region_t *as_define_heap(addrspace_t *as);

#endif