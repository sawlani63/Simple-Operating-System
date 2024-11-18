#include "sharedvm.h"
#include "mapping.h"
#include "frame_table.h"
#include "process.h"
#include <stdlib.h>

/* Macro for getting a page assuming it is already valid. */
#define GET_PAGE(pt, vaddr) pt[(vaddr >> 39) & MASK(9)].l2[(vaddr >> 30) & MASK(9)].l3[(vaddr >> 21) & MASK(9)].l4[(vaddr >> 12) & MASK(9)]

/* Declare a global address space for shared memory. */
addrspace_t *global_addrspace = NULL;

page_upper_directory *global_pagetable_create() {
    global_addrspace = as_create();
    return global_addrspace->page_table;
}

seL4_Error map_shared_region(uintptr_t fault_addr, seL4_CPtr vspace, mem_region_t *shared_region, frame_ref_t ref) {
    if (vaddr_is_mapped(global_addrspace, fault_addr)) {
        /* Free the frame we were given as we already have one. */
        free_frame(ref);

        /* Grab the existing frame in the global address space. */
        ref = GET_PAGE(global_addrspace->page_table, fault_addr).page.frame_ref;

        /* Assign the appropriate rights and attributes for the frame we are about to map. */
        bool canRead = (shared_region->perms & REGION_RD || (shared_region->perms & REGION_EX) >> 2);
        bool canWrite = (shared_region->perms & REGION_WR) >> 1;
        
        seL4_CapRights_t rights;
        if (!canRead && !canWrite) {
            rights = seL4_AllRights;
        } else {
            rights = seL4_CapRights_new(false, false, canRead, canWrite);
        }

        seL4_ARM_VMAttributes attr = seL4_ARM_Default_VMAttributes;
        if (!(shared_region->perms & REGION_EX)) {
            attr |= seL4_ARM_ExecuteNever;
        }

        /* Since this vaddr is already in the global page table, we don't need to map it there again.
         * Simply load it into the user process's VSpace to stop it from faulting the next time. */
        return map_frame(&cspace, ref, vspace, fault_addr, rights, attr);
    }

    /* Map the vaddr into the process's VSpace and the global shadow page table. */
    return sos_map_frame(&cspace, vspace, fault_addr, shared_region->perms, ref, global_addrspace);
}

mem_region_t *insert_shared_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms) {
    /* The convention we choose to follow, is the left-most bit of
     * the perms indicates whether the region is shared or not. */
    return insert_region(addrspace, base, size, perms | BIT(63));
}