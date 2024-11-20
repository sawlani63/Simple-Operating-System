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
        return NULL;
    }

    if (l2_pt[l2_index].l3 == NULL) {
        l2_pt[l2_index].l3 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_table));
    }
    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt == NULL) {
        ZF_LOGE("Failed to allocate level 3 page table");
        free(l2_pt);
        return NULL;
    }

    if (l3_pt[l3_index].l4 == NULL) {
        l3_pt[l3_index].l4 = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
    }
    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        ZF_LOGE("Failed to allocate level 4 page table");
        free(l3_pt);
        free(l2_pt);
        return NULL;
    }

    return &l4_pt[l4_index];
}

extern user_process_t *user_process_list;

int add_shared_region(user_process_t process, void *vaddr, size_t len, uint64_t perms) {
    for (seL4_Word curr_addr = vaddr; curr_addr < vaddr + len; curr_addr += 4096) {
        pt_entry *pte;
        if (!vaddr_is_mapped(global_addrspace, curr_addr)) {
            pte = vaddr_to_page_entry(curr_addr, global_addrspace->page_table);
            pte->valid = 1;
            pte->swapped = 0;
            pte->perms = perms;

            /* Pin any frames allocated as shared */
            frame_ref_t ref = clock_alloc_frame(curr_addr, 0, 1, 0);
            if (ref == NULL_FRAME) {
                ZF_LOGE("Failed to alloc frame");
                return -1;
            }

            /* Since this frame is shared between processes, the pid field is a map 
               where each set position indicates a process holding that frame */
            frame_t *frame = frame_from_ref(ref);
            frame->shared = 1;
            frame->user_frame.pid |= (1 << process.pid);
            pte->page.frame_ref = ref;
            pte->page.frame_cptr = frame_page(ref);
        } else {
            pte = vaddr_to_page_entry(curr_addr, global_addrspace->page_table);
            frame_t *frame = frame_from_ref(pte->page.frame_ref);
            frame->user_frame.pid |= (1 << process.pid);

            /* If the region so far is writeable but a process declares it as read-only, then
               set the region permissions of the global entry and the processes sharing the page
               to read-only. We unmap the hardware page table entry so that it errors out on a vm fault
               if a write is attempted.*/
            if ((perms == REGION_RD) && (pte->perms == (REGION_RD | REGION_WR))) {
                pte->perms = REGION_RD;
                for (int i = 0; i < NUM_PROC; i++) {
                    if (i == process.pid) {
                        continue;
                    }
                    if (frame->user_frame.pid & (1 << i)) {
                        user_process_t user_proc = user_process_list[i];
                        pt_entry *entry = vaddr_to_page_entry(frame->user_frame.vaddr, user_proc.addrspace->page_table);
                        entry->perms = REGION_RD;
                        seL4_CPtr frame_cptr = entry->page.frame_cptr;
                        seL4_Error err = seL4_ARM_Page_Unmap(frame_cptr);
                        if (err) {
                            return -1;
                        }
                        free_untype(&frame_cptr, NULL);
                        entry->page.frame_cptr = seL4_CapNull;

                        mem_region_t tmp = { .base = vaddr + 1 };
                        mem_region_t *reg = sglib_mem_region_t_find_closest_member(user_proc.addrspace->region_tree, &tmp);
                        if (reg != NULL && vaddr < reg->base + reg->size && vaddr >= reg->base) {
                            reg->perms = REGION_RD;
                        }
                    }
                }
            }
        }

        seL4_Error err = sos_map_frame(&cspace, process.vspace, curr_addr,
                                        pte->perms, pte->page.frame_ref,
                                        process.addrspace);
        if (err) {
            return -1;
        }
    }
    return 0;
}

mem_region_t *insert_shared_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms) {
    /* The convention we choose to follow, is the left-most bit of
     * the perms indicates whether the region is shared or not. */
    return insert_region(addrspace, base, size, perms | BIT(63));
}

int unmap_global_entry(seL4_Word vaddr) {
    if (!vaddr_is_mapped(global_addrspace, vaddr)) {
        return 1;
    }

    vaddr_to_page_entry(vaddr, global_addrspace->page_table)->valid = 0;
    return 0;
}