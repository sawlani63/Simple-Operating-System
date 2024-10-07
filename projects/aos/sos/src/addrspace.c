#include <stdlib.h>

#include "addrspace.h"
#include "vmem_layout.h"

addrspace_t *as_create() {
    addrspace_t *as = malloc(sizeof(addrspace_t));
    if (as == NULL) {
		return NULL;
	}

    as->regions = NULL;
    as->page_table = calloc(sizeof(page_upper_directory), PAGE_TABLE_ENTRIES);
    if (as->page_table == NULL) {
        free(as);
        return NULL;
    }

	return as;
}

mem_region_t *as_define_region(addrspace_t *as, seL4_Word vaddr, size_t memsize, unsigned char perms) {
    mem_region_t *region = malloc(sizeof(mem_region_t));
    if (region == NULL) {
        return NULL;
    }
    region->base = vaddr;
    region->size = memsize;
    region->perms = perms;

    mem_region_t *temp = as->regions;
    as->regions = region;
    as->regions->next = temp;

	return region;
}

mem_region_t *as_define_ipc_buff(addrspace_t *as, seL4_Word *initipcbuff) {
    *initipcbuff = PROCESS_IPC_BUFFER;
    return as_define_region(as, PROCESS_IPC_BUFFER, PAGE_SIZE_4K, REGION_RD | REGION_WR);
}

mem_region_t *as_define_stack(addrspace_t *as) {
    return as_define_region(as, PROCESS_STACK_TOP - PAGE_SIZE_4K, PAGE_SIZE_4K, REGION_RD | REGION_WR);
}

mem_region_t *as_define_heap(addrspace_t *as) {
    return as_define_region(as, PROCESS_HEAP_START, 0, REGION_RD | REGION_WR);
}