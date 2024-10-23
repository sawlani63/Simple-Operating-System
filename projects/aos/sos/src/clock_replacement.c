#include "clock_replacement.h"

#define GET_PAGE(pt, vaddr) pt[(vaddr >> 39) & MASK(9)].l2[(vaddr >> 30) & MASK(9)].l3[(vaddr >> 21) & MASK(9)].l4[(vaddr >> 12) & MASK(9)]
#define SWAPMAP_SIZE 128 * 1024    // 128KB in bytes
#define NUM_BLOCKS 1048576        // Total number of 4KB blocks in 4GB (can be stored in an int)

/* 2^19 is the entire frame table size, meaning we can
   cover every page with 2^19 * 8 bytes = 4MB of memory. */
#ifdef CONFIG_SOS_FRAME_LIMIT
    #define BUFFER_SIZE (CONFIG_SOS_FRAME_LIMIT != 0ul ? CONFIG_SOS_FRAME_LIMIT : BIT(19)) - 1
#else
    #define BUFFER_SIZE BIT(19)
#endif

seL4_Word circular_buffer[BUFFER_SIZE - 1];
/* The clock hand pointing to the current position in the circular buffer */
size_t clock_hand = 0;
size_t curr_size = 0;

uint8_t *swap_map;

extern struct user_process user_process;
extern open_file *nfs_pagefile;

extern sync_bin_sem_t *nfs_sem;

// Initialize bitmap (0 means free, 1 means used)
void init_bitmap() {
    swap_map = calloc(SWAPMAP_SIZE, sizeof(uint8_t));
    ZF_LOGF_IF(!swap_map, "Could not initialise swap map!\n");
}

// Mark a block as used (set bit to 1)
void mark_block_used(uint32_t block_num) {
    ZF_LOGF_IF(block_num >= NUM_BLOCKS, "Trying to pass to large of a block number!\n");
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    swap_map[index] |= (1 << bit_index);
}

// Mark a block as free (set bit to 0)
void mark_block_free(uint32_t block_num) {
    ZF_LOGF_IF(block_num >= NUM_BLOCKS, "Trying to pass to large of a block number!\n");
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    swap_map[index] &= ~(1 << bit_index);
}

/* Find first free block (returns block number, or -1 if none found) */
int find_first_free_block() {
    for (uint32_t index = 0; index < SWAPMAP_SIZE; index++) {
        // If not all blocks in this byte are used
        if (swap_map[index] != 0xFF) {
            for (uint8_t bit_index = 0; bit_index < 8; bit_index++) {
                if (!(swap_map[index] & (1 << bit_index))) {
                    return (index * 8) + bit_index;
                }
            }
        }
    }
    return -1;
}

static inline uint32_t get_page_file_offset() {
    int swap_map_index = find_first_free_block();
    ZF_LOGF_IF(swap_map_index < 0, "Could not find a free swap map index!\n");
    mark_block_used(swap_map_index);
    return swap_map_index * PAGE_SIZE_4K;
}

/**
 * Identifies a candidate to page out, and writes it into the paging file on the nfs.
 * The corresponding frame is then unmapped from the hardware page table.
 * @return 0 on success and 1 on failure
 */
static int clock_page_out() {
    addrspace_t *as = user_process.addrspace;
    seL4_Word vaddr;
    pt_entry entry;

    while (1) {
        vaddr = circular_buffer[clock_hand];
        entry = GET_PAGE(as->page_table, vaddr);
        if (entry.page.ref == 0) {
            break;
        }
        entry.page.ref = 0;
        GET_PAGE(as->page_table, vaddr) = entry;
        clock_hand = (clock_hand + 1) % BUFFER_SIZE;
    }
    
    uint32_t file_offset = get_page_file_offset();
    char *data = (char *)frame_data(entry.page.frame_ref);
    nfs_args args = {PAGE_SIZE_4K, data, nfs_sem};
    int res = nfs_pwrite_file(nfs_pagefile->handle, file_offset, data, PAGE_SIZE_4K, nfs_async_write_cb, &args);
    if (res < (int)PAGE_SIZE_4K) {
        return 1;
    }

    seL4_CPtr frame_cptr = entry.page.frame_cptr;
    int err = seL4_ARM_Page_Unmap(frame_cptr);
    ZF_LOGF_IFERR(err, "Failed to unmap page");
    free_untype(&frame_cptr, NULL);
    free_frame(entry.page.frame_ref);

    entry.present = 0;
    entry.swapped = 1;
    entry.swap_map_index = file_offset / PAGE_SIZE_4K;
    GET_PAGE(as->page_table, vaddr) = entry;
    return 0;
}

/**
 * Adds a page in the page table to the clock circular buffer.
 * @param vaddr The virtual address we are adding to our clock cicular buffer
 * @return 0 on success and 1 on failure
 */
static int clock_add_page(seL4_Word vaddr) {
    if (curr_size == BUFFER_SIZE - 1) {
        if (clock_page_out()) {
            return 1;
        }
    } else {
        curr_size++;
    }

    circular_buffer[clock_hand] = vaddr;
    clock_hand = (clock_hand + 1) % (BUFFER_SIZE - 1);
    return 0;
}

frame_ref_t clock_alloc_page(seL4_Word vaddr) {
    clock_add_page(vaddr);
    frame_ref_t frame_ref = alloc_frame();
    ZF_LOGF_IF(frame_ref == NULL_FRAME, "Couldn't allocate a frame in clock_alloc_page!\n");
    return frame_ref;
}

int clock_try_page_in(seL4_Word vaddr) {
    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_upper_directory *l1_pt = user_process.addrspace->page_table;

    if (l1_pt[l1_index].l2 == NULL) {
        return 1;
    }
    if (l1_pt[l1_index].l2[l2_index].l3 == NULL) {
        return 1;
    }
    if (l1_pt[l1_index].l2[l2_index].l3[l3_index].l4 == NULL) {
        return 1;
    }

    pt_entry entry = l1_pt[l1_index].l2[l2_index].l3[l3_index].l4[l4_index];
    if (!entry.valid || entry.present) {
        return 1;
    }
    uint32_t swapmap_pos = GET_PAGE(user_process.addrspace->page_table, vaddr).swap_map_index;

    entry.present = 1;
    entry.page.ref = 1;

    printf("Paged in vaddr %p from swap map offset %d\n", vaddr, swapmap_pos);
    entry.page.frame_ref = clock_alloc_page(vaddr);

    char *data = (char *)frame_data(entry.page.frame_ref);
    nfs_args args = {PAGE_SIZE_4K, data, nfs_sem};
    int res = nfs_pread_file(nfs_pagefile->handle, swapmap_pos * PAGE_SIZE_4K, PAGE_SIZE_4K, nfs_async_read_cb, &args);
    if (res < (int)PAGE_SIZE_4K) {
        return 1;
    }
    mark_block_free(swapmap_pos);

    /* create slot for the frame to load the data into */
    seL4_CPtr frame_cap = cspace_alloc_slot(&cspace);
    if (frame_cap == seL4_CapNull) {
        ZF_LOGD("Failed to alloc slot");
        return 1;
    }
    entry.page.frame_cptr = frame_cap;

    /* copy the frame cptr into the loadee's address space */
    seL4_Error err = cspace_copy(&cspace, frame_cap, &cspace, frame_page(entry.page.frame_ref), seL4_AllRights);
    if (err != seL4_NoError) {
        ZF_LOGD("Failed to untyped reypte");
        return 1;
    }

    GET_PAGE(user_process.addrspace->page_table, vaddr) = entry;
    err = seL4_ARM_Page_Map(frame_cap, user_process.vspace, vaddr, seL4_AllRights, seL4_ARM_Default_VMAttributes);
    ZF_LOGF_IF(err == seL4_FailedLookup, "Failed to map into the HPT in clock_try_page_in!\n");

    return 0;
}