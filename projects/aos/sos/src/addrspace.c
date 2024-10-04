#include <stdlib.h>

#include "addrspace.h"
#include "vmem_layout.h"

addrspace_t *as_create() {
    addrspace_t *as = malloc(sizeof(addrspace_t));
    if (as == NULL) {
		return NULL;
	}

    as->regions = NULL;
    as->heap_top = PROCESS_HEAP_START;
    as->page_table = calloc(sizeof(pt_entry *), PAGE_TABLE_ENTRIES);
    if (as->page_table == NULL) {
        free(as);
        return NULL;
    }

	return as;
}

int as_define_region(addrspace_t *as, seL4_Word vaddr, size_t memsize, unsigned char perms) {
    mem_region_t *region = malloc(sizeof(mem_region_t));
    if (region == NULL) {
        return -1;
    }
    region->base = vaddr;
    region->size = memsize;
    region->perms = perms;

    mem_region_t *temp = as->regions;
    as->regions = region;
    as->regions->next = temp;

	return memsize;
}

int as_define_ipc_buff(addrspace_t *as, seL4_Word *initipcbuff) {
    *initipcbuff = PROCESS_IPC_BUFFER;
    return as_define_region(as, PROCESS_IPC_BUFFER, PAGE_SIZE, REGION_RD | REGION_WR);
}

int as_define_stack(addrspace_t *as, seL4_Word *initstackptr) {
    *initstackptr = PROCESS_STACK_TOP;
    return as_define_region(as, PROCESS_STACK_TOP - PAGE_SIZE, PAGE_SIZE, REGION_RD | REGION_WR);
}

int as_define_heap(addrspace_t *as, seL4_Word *initheapptr) {
    *initheapptr = PROCESS_HEAP_START;
    return as_define_region(as, PROCESS_HEAP_START, 0, REGION_RD | REGION_WR);
}