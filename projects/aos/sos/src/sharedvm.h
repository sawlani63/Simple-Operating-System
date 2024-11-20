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
 * Checks whether the region is in the global address space
 * @return boolean indicating if the region is in the global address space
 */
static inline bool is_shared_region(mem_region_t *region) {
    return region->perms & BIT(63);
}

/**
 * Map the shared region page by page into the process address space (and global address space if not already mapped)
 * @param process the caller process PCB
 * @param vaddr the base of the region
 * @param len the size of the region
 * @param perms the permissions of the region
 * 
 * @return 0 on success
 */
int add_shared_region(user_process_t process, seL4_Word vaddr, size_t len, uint64_t perms);

/**
 * Unmap the page table entry at the given vaddr
 * @param vaddr vaddr of the entry to unmap
 * 
 * @return 0 on success
 */
int unmap_global_entry(seL4_Word vaddr);