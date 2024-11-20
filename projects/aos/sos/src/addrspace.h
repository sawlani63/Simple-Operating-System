#pragma once

#include <cspace/cspace.h>
#include "ut.h"

#define PAGE_TABLE_ENTRIES 0b1 << seL4_VSpaceIndexBits

#define REGION_RD 0x1lu
#define REGION_WR 0x2lu
#define REGION_EX 0x4lu

typedef struct _region {
    seL4_Word base;
    size_t size;
    uint64_t perms; // The leftmost bit indicates whether this is a shared region or not.
    struct _region *left;
    struct _region *right;
    char colour;
} mem_region_t;

typedef size_t frame_ref_t;

/* Needs to sum to 64 bits to be properly byte aligned. */
typedef struct {
    /* A single bit to let us know if this entry is valid/mapped in the page table. */
    size_t valid : 1;
    /* A single bit to let us know whether this entry has been paged out onto disk or not. */
    size_t swapped : 1;
    /* A single bit to let us know whether this entry is part of the global address space or not. */
    size_t shared : 1;
    /* Three bits to indicate the permissions associated with this page entry. */
    size_t perms : 3;
    /* These two structs share the same memory and the one we use depends on the present bit. */
    union {
        struct {
            /* Reference into the frame table. */
            frame_ref_t frame_ref : 19;
            /* Capability to the frame in the Hardware Page Table. */
            seL4_CPtr frame_cptr : 39;
        } page;
        /* Index into the swap map. Large enough to support the entire address space. */
        size_t swap_map_index : 58;
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

/**
 * Initialises a per-process address space and the first level of our page tables
 * @return pointer to the address space struct on success
 */
addrspace_t *as_create();
/**
 * Inserts a region defining the ipc buffer into our address space region_tree
 * @param as the address space to insert the region into
 * @return pointer to the region on success
 */
mem_region_t *as_define_ipc_buff(addrspace_t *as);
/**
 * Inserts a region defining the stack into our address space region_tree
 * @param as the address space to insert the region into
 * @return pointer to the region on success
 */
mem_region_t *as_define_stack(addrspace_t *as);
/**
 * Inserts a region defining the heap into our address space region_tree
 * @param as the address space to insert the region into
 * @return pointer to the region on success
 */
mem_region_t *as_define_heap(addrspace_t *as);

mem_region_t *insert_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms);
mem_region_t *insert_region_at_free_slot(addrspace_t *addrspace, size_t region_size, uint64_t perms);
void remove_region(addrspace_t *addrspace, size_t base);
void free_region_tree(addrspace_t *addrspace);

/* USED ONLY FOR DEBUGGING */
void print_regions(addrspace_t *addrspace);

static inline bool vaddr_in_spt(addrspace_t *addrspace, seL4_Word vaddr) {
    /* We assume the top level is mapped. */
    page_upper_directory *l1_pt = addrspace->page_table;

    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_directory *l2_pt = l1_pt[l1_index].l2;
    if (l2_pt == NULL) {
        return false;
    }

    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt == NULL) {
        return false;
    }

    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        return false;
    }

    return l4_pt[l4_index].valid || l4_pt[l4_index].swapped;
}

static inline bool vaddr_is_mapped(addrspace_t *addrspace, seL4_Word vaddr) {
    /* We assume the top level is mapped. */
    page_upper_directory *l1_pt = addrspace->page_table;

    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_directory *l2_pt = l1_pt[l1_index].l2;
    if (l2_pt == NULL) {
        return false;
    }

    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt == NULL) {
        return false;
    }

    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        return false;
    }

    return l4_pt[l4_index].valid;
}

int check_overlap(addrspace_t *addrspace, size_t base, size_t size);