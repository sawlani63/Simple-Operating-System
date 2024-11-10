#include "clock_replacement.h"

#define GET_PAGE(pt, vaddr) pt[(vaddr >> 39) & MASK(9)].l2[(vaddr >> 30) & MASK(9)].l3[(vaddr >> 21) & MASK(9)].l4[(vaddr >> 12) & MASK(9)]
#define SWAPMAP_SIZE (128 * 1024)                           // 128KB in bytes
#define NUM_BLOCKS (SWAPMAP_SIZE * 8)                       // Total number of 4KB blocks in 4GB (can be stored in an int)
#define QUEUE_SIZE (PAGE_SIZE_4K / sizeof(uint32_t))       // 4KB queue size (1024 entries cached)

struct {
    seL4_Word circular_buffer[NUM_FRAMES];  // Data structure holding the circular buffer
    size_t clock_hand;                      // Current position of the clock hand
    size_t curr_size;                       // Current size of the clock circular buffer

    uint8_t *swap_map;                      // Bitmap of used/free blocks
    uint32_t curr_offset;                   // Current offset into the swap map

    uint32_t *swap_queue;                   // Queue for managing swap map offsets
    size_t queue_head;
    size_t queue_tail;
    size_t queue_size;

    seL4_CPtr page_notif;                   // Notification object to wait on pagefile
} swap_manager = {.clock_hand = 0, .curr_size = 0, .curr_offset = 0, .queue_head = 0, .queue_tail = 0, .queue_size = 0};

extern open_file *nfs_pagefile;

// Initialize bitmap (0 means free, 1 means used)
void init_bitmap() {
    swap_manager.swap_map = calloc(SWAPMAP_SIZE, sizeof(uint8_t));
    ZF_LOGF_IF(!swap_manager.swap_map, "Could not initialise swap map!\n");

    swap_manager.swap_queue = malloc(sizeof(uint32_t) * QUEUE_SIZE);
    ZF_LOGF_IF(!swap_manager.swap_queue, "Could not initialise swap queue!\n");

    alloc_retype(&swap_manager.page_notif, seL4_NotificationObject, seL4_NotificationBits);
}

// Mark a block as used (set bit to 1)
static inline void mark_block_used(uint32_t block_num) {
    ZF_LOGF_IF(block_num >= NUM_BLOCKS, "Trying to pass too large of a block number!\n");
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    swap_manager.swap_map[index] |= (1 << bit_index);
}

// Mark a block as free (set bit to 0)
void mark_block_free(uint32_t block_num) {
    ZF_LOGF_IF(block_num >= NUM_BLOCKS, "Trying to pass too large of a block number!\n");
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    swap_manager.swap_map[index] &= ~(1 << bit_index);
}

/* Find first free block (returns block number, or -1 if none found) */
static int find_free_block_from_index(uint32_t start_index) {
    for (uint32_t index = start_index; index < SWAPMAP_SIZE; index++) {
        // If not all blocks in this byte are used
        if (swap_manager.swap_map[index] != 0xFF) {
            for (uint8_t bit_index = 0; bit_index < 8; bit_index++) {
                if (!(swap_manager.swap_map[index] & (1 << bit_index))) {
                    swap_manager.curr_offset = index + 1;
                    return (index * 8) + bit_index;
                }
            }
        }
    }
    return -1;
}

static inline int find_first_free_block() {
    int free_block = find_free_block_from_index(swap_manager.curr_offset);
    if (free_block != -1) {
        return free_block;
    }

    return find_free_block_from_index(0);
}

static inline uint64_t get_page_file_offset() {
    if (swap_manager.queue_size > 0) {
        uint32_t swap_map_index = swap_manager.swap_queue[swap_manager.queue_head];
        swap_manager.queue_head = (swap_manager.queue_head + 1) % QUEUE_SIZE;
        swap_manager.queue_size--;
        return swap_map_index * PAGE_SIZE_4K;
    }

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
static int clock_page_out(addrspace_t *as) {
    seL4_Word vaddr;
    pt_entry entry;
    while (1) {
        vaddr = swap_manager.circular_buffer[swap_manager.clock_hand];
        entry = GET_PAGE(as->page_table, vaddr);
        if (!vaddr_is_mapped(as, vaddr)) {
            return 0;
        } else if (!entry.pinned) {
            if (entry.page.ref == 0) {
                break;
            }
            GET_PAGE(as->page_table, vaddr).page.ref = 0;
            seL4_Error err = seL4_ARM_Page_Unmap(entry.page.frame_cptr);
            ZF_LOGF_IFERR(err != seL4_NoError, "Failed to unmap page");
        }
        swap_manager.clock_hand = (swap_manager.clock_hand + 1) % NUM_FRAMES;
    }
    
    uint64_t file_offset = get_page_file_offset();
    GET_PAGE(as->page_table, vaddr).pinned = 1;
    sync_bin_sem_wait(data_sem);
    char *data = (char *)frame_data(entry.page.frame_ref);
    sync_bin_sem_post(data_sem);
    io_args args = {PAGE_SIZE_4K, data, swap_manager.page_notif, &GET_PAGE(as->page_table, vaddr)};
    int res = nfs_pwrite_file(nfs_pagefile, data, file_offset, PAGE_SIZE_4K, nfs_pagefile_write_cb, &args);
    if (res < 0) {
        return 1;
    }
    seL4_Wait(swap_manager.page_notif, 0);
    if (args.err < 0) {
        return 1;
    }
    GET_PAGE(as->page_table, vaddr).pinned = 0;

    seL4_CPtr frame_cptr = entry.page.frame_cptr;
    seL4_Error err = seL4_ARM_Page_Unmap(frame_cptr);
    ZF_LOGF_IFERR(err != seL4_NoError, "Failed to unmap page");
    free_untype(&frame_cptr, NULL);
    sync_bin_sem_wait(data_sem);
    free_frame(entry.page.frame_ref);
    sync_bin_sem_post(data_sem);

    pt_entry new_entry = {.valid = 0, .swapped = 1, .pinned = 0 , .perms = GET_PAGE(as->page_table, vaddr).perms,
                          .swap_map_index = file_offset / PAGE_SIZE_4K};
    GET_PAGE(as->page_table, vaddr) = new_entry;
    return 0;
}

int clock_add_page(addrspace_t *as, seL4_Word vaddr) {
    if (swap_manager.curr_size == NUM_FRAMES) {
        if (clock_page_out(as)) {
            return 1;
        }
    } else {
        swap_manager.curr_size++;
    }

    swap_manager.circular_buffer[swap_manager.clock_hand] = vaddr;
    swap_manager.clock_hand = (swap_manager.clock_hand + 1) % NUM_FRAMES;
    return 0;
}

int clock_try_page_in(user_process_t *user_process, seL4_Word vaddr) {
    addrspace_t *as = user_process->addrspace;

    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_upper_directory *l1_pt = as->page_table;
    if (l1_pt[l1_index].l2 == NULL) {
        return 1;
    }

    page_directory *l2_pt = l1_pt[l1_index].l2;
    if (l2_pt[l2_index].l3 == NULL) {
        return 1;
    }

    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt[l3_index].l4 == NULL) {
        return 1;
    }

    pt_entry *l4_pt = l3_pt[l3_index].l4;
    frame_ref_t frame_ref = NULL_FRAME;
    if (l4_pt[l4_index].valid && !l4_pt[l4_index].page.ref) {
        l4_pt[l4_index].page.ref = 1;
        frame_ref = l4_pt[l4_index].page.frame_ref;
    } else if (l4_pt[l4_index].swapped == 1) {
        /* Allocate a new frame to be mapped by the shadow page table. */
        frame_ref = clock_alloc_frame(as, vaddr);
        if (frame_ref == NULL_FRAME) {
            ZF_LOGD("Failed to alloc frame");
            return -1;
        }

        uint64_t file_offset = l4_pt[l4_index].swap_map_index * PAGE_SIZE_4K;
        l4_pt[l4_index].pinned = 1;
        sync_bin_sem_wait(data_sem);
        char *data = (char *)frame_data(frame_ref);
        sync_bin_sem_post(data_sem);
        io_args args = {PAGE_SIZE_4K, data, swap_manager.page_notif, &l4_pt[l4_index]};
        int res = nfs_pread_file(nfs_pagefile, NULL, file_offset, PAGE_SIZE_4K, nfs_pagefile_read_cb, &args);
        if (res < (int)PAGE_SIZE_4K) {
            return -1;
        }
        seL4_Wait(swap_manager.page_notif, 0);
        if (args.err < 0) {
            return 1;
        }
        l4_pt[l4_index].pinned = 0;

        if (swap_manager.queue_size < QUEUE_SIZE) {
            swap_manager.swap_queue[swap_manager.queue_tail] = l4_pt[l4_index].swap_map_index;
            swap_manager.queue_tail = (swap_manager.queue_tail + 1) % QUEUE_SIZE;
            swap_manager.queue_size++;
        }
    } else {
        return 1;
    }

    assert(frame_ref != NULL_FRAME);
    if (sos_map_frame(&cspace, user_process->vspace, vaddr, l4_pt[l4_index].perms, frame_ref, as) != 0) {
        ZF_LOGE("Could not map the frame into the two page tables");
        return -1;
    }
    user_process->size++;
    return 0;
}