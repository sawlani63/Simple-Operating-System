#include <cspace/cspace.h>
#include "frame_table.h"

#define PAGE_SIZE 0x1000
#define PAGE_TABLE_BITS 9
#define PAGE_TABLE_ENTRIES 0b1 << PAGE_TABLE_BITS

#define REGION_RD 0x1
#define REGION_WR 0x2
#define REGION_EX 0x4

typedef struct _region {
    seL4_Word base;
    size_t size;
    unsigned char perms;
    struct _region *next;
} region_t;

struct addrspace {
    frame_ref_t ****page_table;
    region_t *regions;
};

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

struct addrspace *as_create(void);
int as_define_region(struct addrspace *as, seL4_Word vaddr, size_t memsize, unsigned char perms);
int as_define_stack(struct addrspace *as, seL4_Word *initstackptr);