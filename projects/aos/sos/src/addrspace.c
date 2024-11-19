#include <stdlib.h>

#include "addrspace.h"
#include "vmem_layout.h"

/* Define the comparison function for mem_region_t */
int compare_regions(mem_region_t *reg1, mem_region_t *reg2) {
    if (reg1->base < reg2->base) {
        return -1;
    }
    return reg1->base > reg2->base;
}

/* Define the red-black tree type */
SGLIB_DEFINE_RBTREE_FUNCTIONS(mem_region_t, left, right, colour, compare_regions)

/* Function to check if there is an overlap with any existing regions */
int check_overlap(addrspace_t *addrspace, size_t base, size_t size) {
    mem_region_t tmp = { .base = base, .size = size };
    mem_region_t *found = sglib_mem_region_t_find_member(addrspace->region_tree, &tmp);

    if (found) {
        return !(base + size <= found->base || base >= found->base + found->size);
    }
    return 0;
}

/* USED ONLY FOR DEBUGGING */
void print_regions(addrspace_t *addrspace) {
    if (!addrspace || !addrspace->region_tree) {
        printf("No regions to print!\n");
        return;
    }

    printf("\n=== Memory Regions ===\n");
    struct sglib_mem_region_t_iterator it;
    for (mem_region_t *reg = sglib_mem_region_t_it_init(&it, addrspace->region_tree); 
         reg != NULL; 
         reg = sglib_mem_region_t_it_next(&it)) {
        
        printf("Region: base=%p, size=%p, end=%p, perms=", reg->base, reg->size, reg->base + reg->size);
        
        if (reg->perms & REGION_RD) printf("R");
        if (reg->perms & REGION_WR) printf("W");
        if (reg->perms & REGION_EX) printf("X");
        
        if (reg == addrspace->stack_reg) printf(" (Stack)");
        if (reg == addrspace->heap_reg) printf(" (Heap)");
        if (reg == addrspace->below_stack) printf(" (Below Stack)");
        if (reg == addrspace->above_heap) printf(" (Above Heap)");
        
        printf("\n");
    }
    printf("==================\n\n");
}

/* Function to insert a memory region */
mem_region_t *insert_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms) {
    mem_region_t *region = malloc(sizeof(mem_region_t));
    if (region == NULL) {
        printf("No memory for a new region!\n");
        return NULL;
    }

    size_t end = PAGE_ALIGN(base + size + PAGE_SIZE_4K - 1, PAGE_SIZE_4K);
    base = PAGE_ALIGN(base, PAGE_SIZE_4K);
    size = end - base;

    region->base = base;
    region->size = size;
    region->right = region->left = NULL;
    region->colour = 0;
    region->perms = perms;

    if (sglib_mem_region_t_find_member(addrspace->region_tree, region) == NULL) {
        sglib_mem_region_t_add(&(addrspace->region_tree), region);

        mem_region_t *below_stack = addrspace->below_stack;
        if ((addrspace->stack_reg == NULL && base + size < PROCESS_STACK_TOP) ||
            (addrspace->stack_reg != NULL && base + size < addrspace->stack_reg->base &&
            (below_stack == NULL || base + size > below_stack->base + below_stack->size))) {
            addrspace->below_stack = region;
        }

        mem_region_t *heap = addrspace->heap_reg;
        mem_region_t *above_heap = addrspace->above_heap;
        if ((heap == NULL && base > PROCESS_HEAP_START) ||
            (heap != NULL && base > heap->base + heap->size &&
            (above_heap == NULL || base < above_heap->base))) {
            addrspace->above_heap = region;
        }
    } else {
        free(region);
        return NULL;
    }

    return region;
}

/* Function to insert a memory region of given size into the first available free slot */
mem_region_t *insert_region_at_free_slot(addrspace_t *addrspace, size_t region_size, uint64_t perms) {
    size_t last_end = PAGE_SIZE_4K; // We want to keep vaddr 0 as NULL!
    size_t start, end;

    struct sglib_mem_region_t_iterator it;
    mem_region_t *reg;

    for (reg = sglib_mem_region_t_it_init(&it, addrspace->region_tree); 
        reg != NULL; 
        reg = sglib_mem_region_t_it_next(&it)) {

        start = last_end;
        end = start + region_size - 1;

        if (end < reg->base) {
            return insert_region(addrspace, start, region_size, perms);
        }

        last_end = reg->base + reg->size;
    }

    return insert_region(addrspace, last_end, region_size, perms);
}

/* Function to remove a memory region by its start address */
void remove_region(addrspace_t *addrspace, size_t base) {
    mem_region_t tmp = { .base = base };
    mem_region_t *found;

    if (sglib_mem_region_t_delete_if_member(&(addrspace->region_tree), &tmp, &found)) {
        free(found);
    }
    assert(!sglib_mem_region_t_find_member(addrspace->region_tree, &tmp));
}

/* Function to remove a memory region by its start address */
void free_region_tree(addrspace_t *addrspace) {
    struct sglib_mem_region_t_iterator it;
    for (mem_region_t *reg = sglib_mem_region_t_it_init(&it, addrspace->region_tree); reg != NULL; ) {
        mem_region_t *next = sglib_mem_region_t_it_next(&it);
        free(reg);
        reg = next;
    }
}

addrspace_t *as_create() {
    addrspace_t *as = malloc(sizeof(addrspace_t));
    if (as == NULL) {
        printf("No memory for a new address space!\n");
		return NULL;
	}

    as->region_tree = NULL;
    as->page_table = calloc(PAGE_TABLE_ENTRIES, sizeof(page_upper_directory));
    if (as->page_table == NULL) {
        free(as);
        return NULL;
    }
    
    as->stack_reg = NULL;
    as->below_stack = NULL;
    as->heap_reg = NULL;
    as->above_heap = NULL;

	return as;
}

mem_region_t *as_define_ipc_buff(addrspace_t *as) {
    return insert_region(as, PROCESS_IPC_BUFFER, PAGE_SIZE_4K, REGION_RD | REGION_WR);
}

mem_region_t *as_define_stack(addrspace_t *as) {
    return insert_region(as, PROCESS_STACK_TOP - PAGE_SIZE_4K, PAGE_SIZE_4K, REGION_RD | REGION_WR);
}

mem_region_t *as_define_heap(addrspace_t *as) {
    return insert_region(as, PROCESS_HEAP_START, 0, REGION_RD | REGION_WR);
}