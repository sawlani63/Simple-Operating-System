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

int make_shared_region(user_process_t process, void *vaddr, size_t len, bool is_writeable) {
    printf("Got to shared vm, vaddr 0x%lx and len %ld\n", vaddr, len);

    /* Go by page */
    for (seL4_Word curr_addr = vaddr; curr_addr < vaddr + len; curr_addr += 4096) {
        pt_entry *pte;
        if (!vaddr_is_mapped(global_addrspace, curr_addr)) {
            pte = vaddr_to_page_entry(curr_addr, global_addrspace->page_table);
            pte->valid = 1;
            pte->swapped = 0;
            pte->perms = REGION_RD;
            if (is_writeable) {
                pte->perms |= REGION_WR;
            }

            frame_ref_t ref = clock_alloc_frame(curr_addr, 0, 0);
            if (ref == NULL_FRAME) {
                ZF_LOGE("Failed to alloc frame");
                return false;
            }
            frame_from_ref(ref)->shared = 1;
            /* Set the bit at position pid of the process to 1 to indicate the frame being used by that process */
            frame_from_ref(ref)->pid |= (1 << process.pid);
            pte->page.frame_ref = ref;
            pte->page.frame_cptr = frame_page(ref);
        } else {
            pte = vaddr_to_page_entry(curr_addr, global_addrspace->page_table);
            frame_ref_t ref = pte->page.frame_ref;
            frame_from_ref(ref)->pid |= (1 << process.pid);
        }

        seL4_Error err = sos_map_frame(&cspace, process.vspace, curr_addr,
                                        pte->perms, pte->page.frame_ref,
                                        process.addrspace, true);
        if (err) {
            return err;
        }
    }

    printf("Done\n");

    return 0;
}

extern user_process_t *user_process_list;

seL4_Error map_shared_region(uintptr_t fault_addr, user_process_t process, mem_region_t *shared_region) {
    /* If the vaddr is not mapped, map it into the global addrspace with SOS's VSpace. */
    pt_entry *pte;
    if (!vaddr_is_mapped(global_addrspace, fault_addr)) {
        pte = vaddr_to_page_entry(fault_addr, global_addrspace->page_table);
        pte->valid = 1;
        pte->swapped = 0;
        pte->perms = REGION_RD | REGION_WR;

        frame_ref_t ref = clock_alloc_frame(fault_addr, 0, 0);
        if (ref == NULL_FRAME) {
            ZF_LOGE("Failed to alloc frame");
            return false;
        }

        pte->page.frame_ref = ref;
        pte->page.frame_cptr = frame_page(ref);
    } else {
        pte = vaddr_to_page_entry(fault_addr, global_addrspace->page_table);
    }

    seL4_Error err = sos_map_frame(&cspace, process.vspace, fault_addr,
                                REGION_RD | REGION_WR, pte->page.frame_ref,
                                process.addrspace, true);
}

mem_region_t *insert_shared_region(addrspace_t *addrspace, size_t base, size_t size, uint64_t perms) {
    /* The convention we choose to follow, is the left-most bit of
     * the perms indicates whether the region is shared or not. */
    return insert_region(addrspace, base, size, perms | BIT(63));
}

int page_out_shared(frame_t *victim)
{
    seL4_Word vaddr = victim->vaddr;
    for (int i = 0; i < NUM_PROC; i++) {
        if (!(victim->pid & (1 << i))) {
            continue;
        }
        addrspace_t *as = get_process(i).addrspace;
        assert(vaddr_is_mapped(as, vaddr));
        pt_entry entry = GET_PAGE(as->page_table, vaddr);
        seL4_CPtr frame_cptr = entry.page.frame_cptr;
        if (seL4_ARM_Page_Unmap(frame_cptr) != seL4_NoError) {
            return -1;
        }
        free_untype(&frame_cptr, NULL);
        GET_PAGE(as->page_table, vaddr) = (pt_entry){.valid = 0, .swapped = 1, .perms = GET_PAGE(as->page_table, vaddr).perms,
                                                 .swap_map_index = 0};
    }
    return 0;
}

int page_in_shared(frame_ref_t ref, seL4_Word vaddr) {
    pt_entry *pte = vaddr_to_page_entry(vaddr, global_addrspace->page_table);
    pte->valid = 1;
    pte->swapped = 0;
    pte->page.frame_ref = ref;
    pte->page.frame_cptr = frame_page(ref);
    for (int i = 0; i < NUM_PROC; i++) {
        mem_region_t tmp = {.base = vaddr + 1};
        mem_region_t *reg = sglib_mem_region_t_find_closest_member(get_process(i).addrspace->region_tree, &tmp);
        if (reg != NULL && vaddr < reg->base + reg->size && vaddr >= reg->base) {
            if (is_shared_region(reg)) {
                seL4_Error err = sos_map_frame(&cspace, get_process(i).vspace, vaddr, pte->perms, ref, get_process(i).addrspace, true);
                if (err) {
                    return -1;
                }
            }
        }
    }
    return 0;
}

addrspace_t *get_global_addrspace() {
    return global_addrspace;
}