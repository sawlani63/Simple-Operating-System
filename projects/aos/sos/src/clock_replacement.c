#include "clock_replacement.h"
#include "network.h"
#include "mapping.h"
#include "nfs.h"

#include <sync/condition_var.h>

#define GET_PAGE(pt, vaddr) pt[(vaddr >> 39) & MASK(9)].l2[(vaddr >> 30) & MASK(9)].l3[(vaddr >> 21) & MASK(9)].l4[(vaddr >> 12) & MASK(9)]
#define SWAPMAP_SIZE (128 * 1024 * 5)                       // 640KiB in bytes
#define NUM_BLOCKS (SWAPMAP_SIZE * 8)                       // Total number of 4KiB blocks in 20GiB (can be stored in an int)
#define QUEUE_SIZE (PAGE_SIZE_4K / sizeof(uint32_t))        // 4KiB queue size (1024 entries cached)

struct {
    uint8_t *swap_map;                          // Bitmap of used/free blocks
    uint32_t curr_offset;                       // Current offset into the swap map

    uint32_t *swap_queue;                       // Queue for managing swap map offsets
    size_t queue_head;
    size_t queue_tail;
    size_t queue_size;

    seL4_CPtr page_notif;                       // Notification object to wait on pagefile
} swap_manager = {.curr_offset = 0, .queue_head = 0, .queue_tail = 0, .queue_size = 0};

extern open_file *nfs_pagefile;

sync_bin_sem_t *pagefile_sem;
sync_cv_t *pagefile_cv;

// Initialize bitmap (0 means free, 1 means used)
void init_bitmap() {
    swap_manager.swap_map = calloc(SWAPMAP_SIZE, sizeof(uint8_t));
    ZF_LOGF_IF(!swap_manager.swap_map, "Could not initialise swap map!\n");

    swap_manager.swap_queue = malloc(sizeof(uint32_t) * QUEUE_SIZE);
    ZF_LOGF_IF(!swap_manager.swap_queue, "Could not initialise swap queue!\n");

    alloc_retype(&swap_manager.page_notif, seL4_NotificationObject, seL4_NotificationBits);

    pagefile_sem = malloc(sizeof(sync_bin_sem_t));
    seL4_CPtr pagefile_sem_cptr;
    ZF_LOGF_IF(!pagefile_sem, "No memory for semaphore object");
    ut_t *sem_ut = alloc_retype(&pagefile_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(pagefile_sem, pagefile_sem_cptr, 1);

    pagefile_cv = malloc(sizeof(sync_cv_t));
    ZF_LOGF_IF(!pagefile_cv, "No memory for new cv object");
    seL4_CPtr pagefile_cv_cptr;
    sem_ut = alloc_retype(&pagefile_cv_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_cv_init(pagefile_cv, pagefile_cv_cptr);
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

    if (swap_manager.queue_size < QUEUE_SIZE) {
        swap_manager.swap_queue[swap_manager.queue_tail] = block_num;
        swap_manager.queue_tail = (swap_manager.queue_tail + 1) % QUEUE_SIZE;
        swap_manager.queue_size++;
    }
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

frame_t *clock_choose_victim(frame_ref_t *clock_hand, frame_ref_t first) {
    assert(clock_hand != NULL && *clock_hand != NULL_FRAME && first != NULL_FRAME);
    frame_t *curr_frame = frame_from_ref(*clock_hand);
    while (curr_frame->pinned || curr_frame->referenced) {
        curr_frame->referenced = 0;
        *clock_hand = curr_frame->next ? curr_frame->next : first;
        curr_frame = frame_from_ref(*clock_hand);
    }
    return curr_frame;
}

int clock_page_out(frame_t *victim) {
    /* Get the address space specific to the process this frame we are paging out belongs to. */
    addrspace_t *as = get_process(victim->user_frame.pid).addrspace;
    seL4_Word vaddr = victim->user_frame.vaddr;
    
    if (victim->cache) {
        /* Assert that the vaddr is not mapped. Something definitely went wrong if it is. */
        assert(!vaddr_is_mapped(as, vaddr));
        return 0;
    }

    /* Assert that the vaddr we are paging out is actually mapped. Something definitely went wrong if it isn't. */
    assert(vaddr_is_mapped(as, vaddr));

    /* Cache the page table entry, the next free page file offset, the frame data we are paging and the i/o args. */
    pt_entry entry = GET_PAGE(as->page_table, vaddr);
    uint64_t file_offset = get_page_file_offset();
    char *data = (char *)frame_data(entry.page.frame_ref);
    io_args args = {PAGE_SIZE_4K, data, swap_manager.page_notif, NULL, NULL_FRAME, 0};

    /* Perform the actual write to the NFS page file. Wait for it to finish and make sure it succeeds. */
    sync_bin_sem_wait(pagefile_sem);
    int res = nfs_pwrite_file(0, nfs_pagefile, data, file_offset, PAGE_SIZE_4K, nfs_pagefile_write_cb, &args);
    if (res < 0) {
        sync_bin_sem_post(pagefile_sem);
        return -1;
    }
    seL4_Wait(swap_manager.page_notif, 0);
    if (args.err < 0) {
        sync_bin_sem_post(pagefile_sem);
        return -1;
    }
    sync_bin_sem_post(pagefile_sem);

    /* Unmap the entry from the process's vspace and free the frame and its capability. */
    seL4_CPtr frame_cptr = entry.page.frame_cptr;
    if (seL4_ARM_Page_Unmap(frame_cptr) != seL4_NoError) {
        return -1;
    }
    free_untype(&frame_cptr, NULL);
    free_frame(entry.page.frame_ref);

    /* Update our shadow page table mapping to mark it as invalid, swapped and store its index in the page file. */
    GET_PAGE(as->page_table, vaddr) = (pt_entry){.valid = 0, .swapped = 1, .perms = GET_PAGE(as->page_table, vaddr).perms,
                                                 .swap_map_index = file_offset / PAGE_SIZE_4K};
    return 0;
}

int clock_try_page_in(user_process_t *user_process, seL4_Word vaddr) {
    addrspace_t *as = user_process->addrspace;

    /* If the vaddr is not in the shadow page table to start with, return and continue in vm fault. */
    if (!vaddr_in_spt(as, vaddr)) {
        return 1;
    }

    pt_entry entry = GET_PAGE(as->page_table, vaddr);
    frame_ref_t ref = NULL_FRAME;
    if (entry.valid) {
        sync_bin_sem_wait(data_sem);
        frame_t *frame = frame_from_ref(entry.page.frame_ref);
        if (!frame->referenced) {
            frame->referenced = 1;
            ref = entry.page.frame_ref;
        }
        sync_bin_sem_post(data_sem);
    } else if (entry.swapped) {
        /* Assert that the vaddr we are paging in is not mapped. Something definitely went wrong if it is. */
        assert(!vaddr_is_mapped(as, vaddr));

        /* Allocate a new frame to be mapped by the shadow page table. Start the frame off as pinned. */
        ref = clock_alloc_frame(vaddr, user_process->pid, 1, 0);
        if (ref == NULL_FRAME) {
            ZF_LOGD("Failed to alloc frame");
            return -1;
        }

        /* Grab the offset into the swap file and load PAGE_SIZE_4K bytes into the newly alloc'd frame. */
        uint64_t file_offset = entry.swap_map_index * PAGE_SIZE_4K;
        sync_bin_sem_wait(data_sem);
        char *data = (char *)frame_data(ref);
        io_args args = {PAGE_SIZE_4K, data, swap_manager.page_notif, NULL, NULL_FRAME, 0};
        sync_bin_sem_wait(pagefile_sem);
        int res = nfs_pread_file(user_process->pid, nfs_pagefile, NULL, file_offset, PAGE_SIZE_4K, nfs_pagefile_read_cb, &args);
        if (res < (int)PAGE_SIZE_4K) {
            sync_bin_sem_post(pagefile_sem);
            sync_bin_sem_post(data_sem);
            return -1;
        }
        seL4_Wait(swap_manager.page_notif, 0);
        if (args.err < 0) {
            sync_bin_sem_post(pagefile_sem);
            sync_bin_sem_post(data_sem);
            return 1;
        }
        unpin_frame(ref);
        sync_bin_sem_post(pagefile_sem);
        sync_bin_sem_post(data_sem);

        /* Update our swap manager bitmap and queue to cache the newly unused file offset. */
        mark_block_free(entry.swap_map_index);
    } else {
        ZF_LOGV("Unexpected case in clock_try_page_in! Continuing to vm fault.");
        return 1;
    }

    /* Assert the frame we got is not null as a sanity check, and map the new frame into the process's vspace. */
    assert(frame_from_ref(ref) != NULL);
    if (sos_map_frame(&cspace, user_process->vspace, vaddr, entry.perms, ref, as) != 0) {
        ZF_LOGE("Could not map the frame into the two page tables");
        return -1;
    }
    return 0;
}