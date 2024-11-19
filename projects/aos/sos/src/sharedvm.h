#pragma once

#include "process.h"

/**
 * Initialises a global page table
 * @return pointer to the address space struct on success
 */
page_upper_directory *global_pagetable_create();

/**
 * Initialises a shared region into process's address space
 * @return pointer to the global memory region on success
 */
mem_region_t *insert_shared_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms);

/**
 * Maps the shared region into the process's vspace and the global shadow page table
 * @return pointer to the global memory region on success
 */
seL4_Error map_shared_region(uintptr_t fault_addr, user_process_t process, mem_region_t *shared_region);

/**
 * Checks whether the region is in the global address space
 * @return boolean indicating if the region is in the global address space
 */
static inline bool is_shared_region(mem_region_t *region) {
    return region->perms & BIT(63);
}

int make_shared_region(user_process_t process, void *vaddr, size_t len, bool is_writeable);
addrspace_t *get_global_addrspace();