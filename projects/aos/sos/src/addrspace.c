#include <stdlib.h>

#include "addrspace.h"
#include "vmem_layout.h"

struct addrspace *as_create(void) {
    struct addrspace *as = malloc(sizeof(struct addrspace));
    if (as == NULL) {
		return NULL;
	}

    as->regions = NULL;
    as->page_table = malloc(sizeof(frame_ref_t) * PAGE_TABLE_ENTRIES);
    if (as->page_table == NULL) {
        free(as);
        return NULL;
    }
    
    for (int i = 0; i < PAGE_TABLE_ENTRIES; i++){
        as->page_table[i] = NULL;
    }

	return as;
}

int as_define_region(struct addrspace *as, seL4_Word vaddr, size_t memsize, unsigned char perms) {
    region_t *region = malloc(sizeof(region_t));
    if (region == NULL) {
        return -1;
    }
    region->base = vaddr;
    region->size = memsize;
    region->perms = perms;

    region_t *temp = as->regions;
    as->regions = region;
    as->regions->next = temp;

	return 0;
}

int as_define_ipc_buff(struct addrspace *as, seL4_Word *initipcbuff) {
    *initipcbuff = PROCESS_IPC_BUFFER;
    return as_define_region(as, PROCESS_IPC_BUFFER, PAGE_SIZE, REGION_RD | REGION_WR);
}

int as_define_stack(struct addrspace *as, seL4_Word *initstackptr) {
    *initstackptr = PROCESS_STACK_TOP;
    return as_define_region(as, PROCESS_STACK_TOP - PAGE_SIZE, PAGE_SIZE, REGION_RD | REGION_WR);
}