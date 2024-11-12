#pragma once

#include "sos_syscall.h"

/**
 * Initialises the bitmap / swap map.
 */
void init_bitmap();

/**
 * Marks a block or frame in the page file as free.
 * @param vaddr The block number associated with a frame.
 */
void mark_block_free(uint32_t block_num);

/**
 * Adds a page in the page table to the clock circular buffer, and pages out another
 * page if necessary.
 * @param vaddr The virtual address we are adding to our clock cicular buffer
 * @return 0 on success and 1 on failure
 */
int clock_add_page(user_process_t process, seL4_Word vaddr);

int clock_try_page_in(user_process_t *user_process, seL4_Word vaddr);

void clock_invalidate_process(pid_t pid);

int clock_page_out(user_process_t process);

extern sync_bin_sem_t *data_sem;

static inline frame_ref_t clock_alloc_frame(user_process_t process, seL4_Word vaddr) {
    clock_add_page(process, vaddr);
    sync_bin_sem_wait(data_sem);
    frame_ref_t ref = alloc_frame();
    sync_bin_sem_post(data_sem);
    return ref;
}