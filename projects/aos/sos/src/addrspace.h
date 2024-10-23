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
    struct _region *left;
    struct _region *right;
    char colour;
} mem_region_t;

/* Needs to sum to 64 bits to be properly byte aligned. */
typedef struct {
    /* A single bit to let us know if this is entry is present in the page table. */
    size_t present : 1;
    /* A single bit to let us know whether this entry has been swapped out or not */
    size_t swapped : 1;
    /* Four bits to indicate the permissions associated with this page entry */
    size_t perms : 4;
    /* These two structs share the same memory and the one we use depends on the present bit. */
    union {
        struct {
            /* Reference bit to indicate whether this page was recently referenced */
            size_t ref : 1;
            /* Reference into the frame table. */
            frame_ref_t frame_ref : 19;
            /* Capability to the frame in the Hardware Page Table. */
            seL4_CPtr frame_cptr : 38;
        } page;
        /* Index into the swap map. Large enough to support the entire address space. */
        size_t swap_map_index : 20;
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
    mem_region_t *region_tree;

    mem_region_t *stack_reg;
    mem_region_t *below_stack;

    mem_region_t *heap_reg;
    mem_region_t *above_heap;
} addrspace_t;

SGLIB_DEFINE_RBTREE_PROTOTYPES(mem_region_t, left, right, colour, compare_regions)

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
mem_region_t *as_define_ipc_buff(addrspace_t *as);
mem_region_t *as_define_stack(addrspace_t *as);
mem_region_t *as_define_heap(addrspace_t *as);

mem_region_t *insert_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms);
mem_region_t *insert_region_at_free_slot(addrspace_t *addrspace, size_t region_size, uint64_t perms);
void remove_region(addrspace_t *addrspace, size_t base);

/* USED ONLY FOR DEBUGGING */
void print_regions(addrspace_t *addrspace);

#endif