#ifndef ADDRSPACE
#define ADDRSPACE

#include <cspace/cspace.h>
#include "frame_table.h"

#define PAGE_TABLE_ENTRIES 0b1 << seL4_VSpaceIndexBits

#define REGION_RD 0x1lu
#define REGION_WR 0x2lu
#define REGION_EX 0x4lu

typedef struct _region {
    seL4_Word base;
    size_t size;
    uint64_t perms;
    struct _region *next;
} mem_region_t;

/* Needs to sum to 64 bits to be properly byte aligned. */
typedef struct {
    /* A single bit to let us know if this is entry is present in the page table. */
    size_t present : 1;
    /* These two structs share the same memory and the one we use depends on the present bit. */
    union {
        struct {
            /* Reference into the frame table. */
            frame_ref_t frame_ref : 19;
            /* Capability to the frame in the Hardware Page Table. */
            seL4_CPtr frame_cptr : 43;
            /* A bit to indicate whether a page has been recently referenced or not. */
            seL4_CPtr referenced : 1;
        } page;
        
        struct {
            /* Position in the nfs paging file the page entry is stored in. */
            size_t file_position : 52;
            /* Unused bits which we can change later if we find a use for them. */
            size_t unused : 11;
        } swapped;
    };
} PACKED pt_entry;

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