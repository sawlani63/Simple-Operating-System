/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#include <sel4/sel4.h>
#include <sel4/sel4_arch/mapping.h>

#include "mapping.h"
#include "ut.h"
#include "vmem_layout.h"

/**
 * Retypes and maps a page table into the root servers page global directory
 * @param cspace that the cptrs refer to
 * @param vaddr  the virtual address of the mapping
 * @param ut     a 4k untyped object
 * @param empty  an empty slot to retype into a pt
 * @return 0 on success
 */
static seL4_Error retype_map_pt(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut, seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageTableObject, seL4_PageBits);
    if (err) {
        return err;
    }

    return seL4_ARM_PageTable_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}

/**
 * Retypes and maps a page directory into the root servers page global directory
 * @param cspace that the cptrs refer to
 * @param vaddr  the virtual address of the mapping
 * @param ut     a 4k untyped object
 * @param empty  an empty slot to retype into a pd
 * @return 0 on success
 */
static seL4_Error retype_map_pd(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut, seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageDirectoryObject, seL4_PageBits);
    if (err) {
        return err;
    }

    return seL4_ARM_PageDirectory_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}

/**
 * Retypes and maps a page upper directory into the root servers page global directory
 * @param cspace that the cptrs refer to
 * @param vaddr  the virtual address of the mapping
 * @param ut     a 4k untyped object
 * @param empty  an empty slot to retype into a pud
 * @return 0 on success
 */
static seL4_Error retype_map_pud(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr, seL4_CPtr ut,
                                 seL4_CPtr empty)
{

    seL4_Error err = cspace_untyped_retype(cspace, ut, empty, seL4_ARM_PageUpperDirectoryObject, seL4_PageBits);
    if (err) {
        return err;
    }
    return seL4_ARM_PageUpperDirectory_Map(empty, vspace, vaddr, seL4_ARM_Default_VMAttributes);
}

seL4_Error map_frame_impl(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                          seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                          seL4_CPtr *free_slots, seL4_Word *used, page_upper_directory *page_table)
{
    /* We use our shadow page table which follows the same structure as the hardware one.
    * Check the seL4 Manual section 7.1.1 for hardware virtual memory objects. Importantly
    * the top-most 16 bits of the virtual address are unused bits, so we ignore them. */
    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */

    /* Page align the vaddr */
    vaddr &= ~(PAGE_SIZE_4K - 1);

    /* Attempt the mapping */
    seL4_Error err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
    for (size_t i = 0; i < MAPPING_SLOTS && err == seL4_FailedLookup; i++) {
        /* save this so nothing else trashes the message register value */
        seL4_Word failed = seL4_MappingFailedLookupLevel();

        /* Assume the error was because we are missing a paging structure */
        ut_t *ut = ut_alloc_4k_untyped(NULL);
        if (ut == NULL) {
            ZF_LOGE("Out of 4k untyped");
            return -1;
        }

        /* figure out which cptr to use to retype into*/
        seL4_CPtr slot;
        if (used != NULL) {
            slot = free_slots[i];
            *used |= BIT(i);
        } else {
            slot = cspace_alloc_slot(cspace);
        }

        if (slot == seL4_CapNull) {
            ZF_LOGE("No cptr to alloc paging structure");
            return -1;
        }

        switch (failed) {
        case SEL4_MAPPING_LOOKUP_NO_PT:
            err = retype_map_pt(cspace, vspace, vaddr, ut->cap, slot);
            if (page_table != NULL) {
                page_table[l1_index].l2[l2_index].l3[l3_index].ut = ut;
                page_table[l1_index].l2[l2_index].l3[l3_index].slot = slot;
            }
            break;
        case SEL4_MAPPING_LOOKUP_NO_PD:
            err = retype_map_pd(cspace, vspace, vaddr, ut->cap, slot);
            if (page_table != NULL) {
                page_table[l1_index].l2[l2_index].ut = ut;
                page_table[l1_index].l2[l2_index].slot = slot;
            }
            break;
        case SEL4_MAPPING_LOOKUP_NO_PUD:
            err = retype_map_pud(cspace, vspace, vaddr, ut->cap, slot);
            if (page_table != NULL) {
                page_table[l1_index].ut = ut;
                page_table[l1_index].slot = slot;
            }
            break;
        }

        if (!err) {
            /* Try the mapping again */
            err = seL4_ARM_Page_Map(frame_cap, vspace, vaddr, rights, attr);
        }
    }

    return err;
}

seL4_Error map_frame_cspace(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                            seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                            seL4_CPtr free_slots[MAPPING_SLOTS], seL4_Word *used)
{
    if (cspace == NULL) {
        ZF_LOGE("Invalid arguments");
        return -1;
    }
    return map_frame_impl(cspace, frame_cap, vspace, vaddr, rights, attr, free_slots, used, NULL);
}

seL4_Error map_frame(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                     seL4_CapRights_t rights, seL4_ARM_VMAttributes attr)
{
    return map_frame_impl(cspace, frame_cap, vspace, vaddr, rights, attr, NULL, NULL, NULL);
}

seL4_Error sos_map_frame_cspace(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                                seL4_CapRights_t rights, seL4_ARM_VMAttributes attr, seL4_CPtr *free_slots,
                                seL4_Word *used, page_upper_directory *page_table)
{
    return map_frame_impl(cspace, frame_cap, vspace, vaddr, rights, attr, free_slots, used, page_table);
}

seL4_Error sos_map_frame(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr,
                         size_t perms, frame_ref_t frame_ref, addrspace_t *as)
{
    /* We assume SOS provided us with a valid, unmapped vaddr and isn't confusing any permissions. */

    /* We use our shadow page table which follows the same structure as the hardware one.
     * Check the seL4 Manual section 7.1.1 for hardware virtual memory objects. Importantly
     * the top-most 16 bits of the virtual address are unused bits, so we ignore them. */
    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_upper_directory *l1_pt = as->page_table;

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
        return seL4_NotEnoughMemory;
    }

    if (l3_pt[l3_index].l4 == NULL) {
        l3_pt[l3_index].l4 = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
    }
    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        ZF_LOGE("Failed to allocate level 4 page table");
        return seL4_NotEnoughMemory;
    }

    /* create slot for the frame to load the data into */
    seL4_CPtr frame_cap = cspace_alloc_slot(cspace);
    if (frame_cap == seL4_CapNull) {
        ZF_LOGD("Failed to alloc slot");
        return 1;
    }

    /* copy the frame cptr into the loadee's address space */
    seL4_Error err = cspace_copy(cspace, frame_cap, cspace, frame_page(frame_ref), seL4_AllRights);
    if (err != seL4_NoError) {
        ZF_LOGD("Failed to untyped reypte");
        return err;
    }

    pt_entry entry = {.valid = 1, .swapped = 0, .pinned = 0, .perms = perms, .page = {1, frame_ref, frame_cap}};
    if (vaddr == PROCESS_IPC_BUFFER) {
        entry.pinned = 1;
    }
    l4_pt[l4_index] = entry;

    /* Assign the appropriate rights and attributes for the frame we are about to map. */
    bool canRead = (perms & REGION_RD || (perms & REGION_EX) >> 2);
    bool canWrite = (perms & REGION_WR) >> 1;

    seL4_CapRights_t rights;
    if (!canRead && !canWrite) {
        rights = seL4_AllRights;
    } else {
        rights = seL4_CapRights_new(false, false, canRead, canWrite);
    }

    seL4_ARM_VMAttributes attr = seL4_ARM_Default_VMAttributes;
    if (!(perms & REGION_EX)) {
        attr |= seL4_ARM_ExecuteNever;
    }

    return map_frame_impl(cspace, frame_cap, vspace, vaddr, rights, attr, NULL, NULL, l1_pt);
}

void sos_destroy_page_table(addrspace_t *as)
{
    page_upper_directory *l1_pt = as->page_table;
    for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
        page_directory *l2_pt = l1_pt[i].l2;
        if (l2_pt == NULL) {
            continue;
        }
        for (size_t j = 0; j < PAGE_TABLE_ENTRIES; j++) {
            page_table *l3_pt = l2_pt[j].l3;
            if (l3_pt == NULL) {
                continue;
            }
            for (size_t k = 0; k < PAGE_TABLE_ENTRIES; k++) {
                pt_entry *l4_pt = l3_pt[k].l4;
                if (l4_pt == NULL) {
                    continue;
                }
                for (size_t m = 0; m < PAGE_TABLE_ENTRIES; m++) {
                    pt_entry entry = l4_pt[m];
                    if (entry.valid == 0 && entry.swapped == 0) {
                        continue;
                    }
                    seL4_CPtr frame_cptr = entry.page.frame_cptr;
                    seL4_Error err = seL4_ARM_Page_Unmap(frame_cptr);
                    if (err != seL4_NoError) {
                        ZF_LOGE("Failed to unmap");
                        return;
                    }
                    free_untype(&frame_cptr, NULL);
                    free_frame(entry.page.frame_ref);
                    l4_pt[m] = (pt_entry){0};
                }
                free(l4_pt);
            }
        }
    }

    for (size_t i = 0; i < PAGE_TABLE_ENTRIES; i++) {
        page_directory *l2_pt = l1_pt[i].l2;
        if (l2_pt == NULL) {
            continue;
        }
        for (size_t j = 0; j < PAGE_TABLE_ENTRIES; j++) {
            page_table *l3_pt = l2_pt[j].l3;
            if (l3_pt == NULL) {
                continue;
            }
            for (size_t k = 0; k < PAGE_TABLE_ENTRIES; k++) {
                if (l3_pt[k].slot != seL4_CapNull) {
                    seL4_Error err = seL4_ARM_PageTable_Unmap(l3_pt[k].slot);
                    if (err != seL4_NoError) {
                        ZF_LOGE("Failed to unmap");
                        return;
                    }
                }
                free_untype(&l3_pt[k].slot, l3_pt[k].ut);
            }
            if (l2_pt[j].slot != seL4_CapNull) {
                seL4_Error err = seL4_ARM_PageTable_Unmap(l2_pt[j].slot);
                if (err != seL4_NoError) {
                    ZF_LOGE("Failed to unmap");
                    return;
                }
            }
            free_untype(&l2_pt[j].slot, l2_pt[j].ut);
            free(l3_pt);
        }
        if (l1_pt[i].slot != seL4_CapNull) {
            seL4_Error err = seL4_ARM_PageTable_Unmap(l1_pt[i].slot);
            if (err != seL4_NoError) {
                ZF_LOGE("Failed to unmap");
                return;
            }
        }
        free_untype(&l1_pt[i].slot, l1_pt[i].ut);
        free(l2_pt);
    }
    free(l1_pt);
}

static uintptr_t device_virt = SOS_DEVICE_START;

void *sos_map_device(cspace_t *cspace, uintptr_t addr, size_t size)
{
    assert(cspace != NULL);
    void *vstart = (void *) device_virt;

    for (uintptr_t curr = addr; curr < (addr + size); curr += PAGE_SIZE_4K) {
        ut_t *ut = ut_alloc_4k_device(curr);
        if (ut == NULL) {
            ZF_LOGE("Failed to find ut for phys address %p", (void *) curr);
            return NULL;
        }

        /* allocate a slot to retype into */
        seL4_CPtr frame = cspace_alloc_slot(cspace);
        if (frame == seL4_CapNull) {
            ZF_LOGE("Out of caps");
            return NULL;
        }

        /* retype */
        seL4_Error err = cspace_untyped_retype(cspace, ut->cap, frame, seL4_ARM_SmallPageObject,
                                               seL4_PageBits);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to retype %lx", (seL4_CPtr)ut->cap);
            cspace_free_slot(cspace, frame);
            return NULL;
        }

        /* map */
        err = map_frame(cspace, frame, seL4_CapInitThreadVSpace, device_virt, seL4_AllRights, false);
        if (err != seL4_NoError) {
            ZF_LOGE("Failed to map device frame at %p", (void *) device_virt);
            cspace_delete(cspace, frame);
            cspace_free_slot(cspace, frame);
            return NULL;
        }

        device_virt += PAGE_SIZE_4K;
    }

    return vstart;
}
