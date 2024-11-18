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

pt_entry *vaddr_to_page_entry(uintptr_t fault_addr, page_upper_directory *l1_pt) {
    uint16_t l1_index = (fault_addr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (fault_addr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (fault_addr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (fault_addr >> 12) & MASK(9); /* Next 9 bits */

    /* Allocate any necessary levels within the shadow page table. */
    if (l1_pt[l1_index].l2 == NULL) {
        l1_pt[l1_index].l2 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_directory));
    }
    page_directory *l2_pt = l1_pt[l1_index].l2;
    if (l2_pt == NULL) {
        ZF_LOGE("Failed to allocate level 2 page table");
        return seL4_NotEnoughMemory;
    }

    if (l2_pt[l2_index].l3 == NULL) {
        l2_pt[l2_index].l3 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_table));
    }
    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt == NULL) {
        ZF_LOGE("Failed to allocate level 3 page table");
        free(l2_pt);
        return seL4_NotEnoughMemory;
    }

    if (l3_pt[l3_index].l4 == NULL) {
        l3_pt[l3_index].l4 = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
    }
    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        ZF_LOGE("Failed to allocate level 4 page table");
        free(l3_pt);
        free(l2_pt);
        return seL4_NotEnoughMemory;
    }

    return &l4_pt[l4_index];
}

extern user_process_t *user_process_list;

seL4_Error map_shared_region(uintptr_t fault_addr, user_process_t process, mem_region_t *shared_region) {
    /* If the vaddr is not mapped, map it into the global addrspace with SOS's VSpace. */
    if (!vaddr_is_mapped(global_addrspace, fault_addr)) {
        frame_ref_t ref = clock_alloc_frame(fault_addr, process.pid, 0);
        if (ref == NULL_FRAME) {
            ZF_LOGE("Failed to alloc frame");
            return false;
        }
        uint16_t l1_index = (fault_addr >> 39) & MASK(9); /* Top 9 bits */
        uint16_t l2_index = (fault_addr >> 30) & MASK(9); /* Next 9 bits */
        uint16_t l3_index = (fault_addr >> 21) & MASK(9); /* Next 9 bits */
        uint16_t l4_index = (fault_addr >> 12) & MASK(9); /* Next 9 bits */

        page_upper_directory *l1_pt = global_addrspace->page_table;

        /* Allocate any necessary levels within the shadow page table. */
        if (l1_pt[l1_index].l2 == NULL) {
            l1_pt[l1_index].l2 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_directory));
        }
        page_directory *l2_pt = l1_pt[l1_index].l2;
        if (l2_pt == NULL) {
            ZF_LOGE("Failed to allocate level 2 page table");
            return seL4_NotEnoughMemory;
        }

        if (l2_pt[l2_index].l3 == NULL) {
            l2_pt[l2_index].l3 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_table));
        }
        page_table *l3_pt = l2_pt[l2_index].l3;
        if (l3_pt == NULL) {
            ZF_LOGE("Failed to allocate level 3 page table");
            free(l2_pt);
            return seL4_NotEnoughMemory;
        }

        if (l3_pt[l3_index].l4 == NULL) {
            l3_pt[l3_index].l4 = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
        }
        pt_entry *l4_pt = l3_pt[l3_index].l4;
        if (l4_pt == NULL) {
            ZF_LOGE("Failed to allocate level 4 page table");
            free(l3_pt);
            free(l2_pt);
            return seL4_NotEnoughMemory;
        }

        pt_entry entry = {.valid = 1, .swapped = 0, .perms = REGION_RD | REGION_WR, .page = {ref, frame_page(ref)}};
        l4_pt[l4_index] = entry;
        printf("\nmakign region for first time\n");
    } else {
        printf("going to existing region: %s\n", frame_data(GET_PAGE(global_addrspace->page_table, fault_addr).page.frame_ref));
        printf("going to existing region: %s\n", frame_data(GET_PAGE(user_process_list[1].addrspace->page_table, fault_addr).page.frame_ref));
    }

    /* Grab the existing frame in the global address space. */
    frame_ref_t ref = GET_PAGE(global_addrspace->page_table, fault_addr).page.frame_ref;
    return sos_map_frame(&cspace, process.vspace, fault_addr, REGION_RD | REGION_WR, ref, process.addrspace, true);
}

mem_region_t *insert_shared_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms) {
    /* The convention we choose to follow, is the left-most bit of
     * the perms indicates whether the region is shared or not. */
    return insert_region(addrspace, base, size, perms | BIT(63));
}