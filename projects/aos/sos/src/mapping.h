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
#pragma once

#include <stdbool.h>
#include "addrspace.h"
#include "utils.h"
#include "threads.h"

seL4_Error map_frame_impl(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                          seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                          seL4_CPtr *free_slots, seL4_Word *used, page_upper_directory *page_table);

/**
 * Maps a page.
 *
 * Intermediate paging structures will be created if required, but empty slots must be provided to
 * allocate them.
 *
 * This function is used by the bootstrapped cspace to allocate new bookkeeping data. To avoid
 * infinite recursion, we provide MAPPING_SLOTS free slots to this function: pre allocated slots
 * which we know are free. Without this, allocating a slot could cause recursion into the map_frame
 * function, which could then recurse back to allocating slots... etc.
 *
 *
 * @param cspace          CSpace which can be used to retype slots.
 * @param frame_cap       A capbility to the frame to be mapped (seL4_ARM_SmallPageObject).
 * @param vspace          A capability to the vspace (seL4_ARM_PageGlobalDirectoryObject).
 * @param vaddr           The virtual address to map the frame.
 * @param rights          The access rights for the mapping
 * @param attr            The VM attributes to use for the mapping
 * @param free_slots      free slots in cspace to use in case paging structures must be allocated.
 * @param[out] used       the function will mark each bit for each slot used.
 *                        e.g if slot 0 is used, BIT(0) in used will be set.
 * @return 0 on success
 */
seL4_Error map_frame_cspace(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                            seL4_CapRights_t rights, seL4_ARM_VMAttributes attr,
                            seL4_CPtr free_slots[MAPPING_SLOTS], seL4_Word *used);


/* Maps a page, allocating intermediate structures and cslots with the cspace provided.
 *
 * If you *know* you can map the vaddr without allocating any other paging structures, or that it is
 * safe to allocate cslots, you can provide NULL as the cspace.
 *
 * @param cspace          CSpace which can be used to allocate slots for intermediate paging structures.
 * @param frame_cap       A capbility to the frame to be mapped (seL4_ARM_SmallPageObject).
 * @param vspace          A capability to the vspace (seL4_ARM_PageGlobalDirectoryObject).
 * @param vaddr           The virtual address to map the frame.
 * @param rights          The access rights for the mapping
 * @param attr            The VM attributes to use for the mapping
 *
 * @return 0 on success
 */
seL4_Error map_frame(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr, seL4_CapRights_t rights,
                     seL4_ARM_VMAttributes attr);

seL4_Error sos_map_frame_cspace(cspace_t *cspace, seL4_CPtr frame_cap, seL4_CPtr vspace, seL4_Word vaddr,
                                seL4_CapRights_t rights, seL4_ARM_VMAttributes attr, seL4_CPtr *free_slots,
                                seL4_Word *used, page_upper_directory *page_table);

/** Maps a page, allocating intermediate structures and cslots with the cspace provided.
 *
 * If you *know* you can map the vaddr without allocating any other paging structures, or that it is
 * safe to allocate cslots, you can provide NULL as the cspace.

 * Along with allocating intermediate structures and cslots within the provided cspace, we also allocate
 * a slot within a "shadow" page table. This shadow page table maps virtual memory to a capability
 * stored within the hardware page table. This shadow structure is necessary for us to keep track of the
 * capabilities to physical frames so that we can later free them and approve/deny requests to perform
 * actions on memory based off user permisions (recorded in regions within the address space).
 *
 * @param cspace          cspace used to retype slots
 * @param vspace          A capability to the vspace (seL4_ARM_PageGlobalDirectoryObject).
 * @param vaddr           The virtual address to map the frame.
 * @param perms           The access rights for the mapping
 * @param frame_ref       The frame reference to map
 * @param as              The address space of the process
 *
 * @return 0 on success
 */
seL4_Error sos_map_frame(cspace_t *cspace, seL4_CPtr vspace, seL4_Word vaddr,
                         size_t perms, frame_ref_t frame_ref, addrspace_t *as);

/**
 * Cleans up the memory allocated for our shadow page table and unmaps 
 * all the pages and page tables mapped in our vspace.
 * 
 * @param as The address space of the process being deleted
 */
void sos_destroy_page_table(addrspace_t *as);

/*
 * Map a device and return the virtual address it is mapped to.
 *
 * @param cspace cspace to use to allocate slots
 * @param addr   physical address of the device
 * @param size   size of the device in bytes
 * @return address that the device is mapped at.
 * */
void *sos_map_device(cspace_t *cspace, uintptr_t addr, size_t size, seL4_CPtr vspace, seL4_CPtr frame_cap, bool timer);

void sos_map_timer(cspace_t *cspace, uintptr_t addr, size_t size, seL4_CPtr vspace, seL4_CPtr frame, void *timer_vaddr);
