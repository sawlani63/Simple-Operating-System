#pragma once

#include "frame_table.h"
#include "process.h"

/**
 * Initialises the bitmap / swap map.
 */
void init_bitmap();
extern sync_bin_sem_t *data_sem;

/**
 * Marks a given block number in the swap map as free
 * @param block_num the block number to mark as free in the swap map
 */
void mark_block_free(uint32_t block_num);

/**
 * Function to choose a victim frame to page out
 * @param clock_hand the current position of the circular buffer
 * @param first the very first frame in the frame table incase the clock hand needs to wrap around
 */
frame_t *clock_choose_victim(frame_ref_t *clock_hand, frame_ref_t first);

/**
 * Function to page out frames
 * @param victim pointer to the frame we are paging out
 * 
 * @return 0 on success
 */
int clock_page_out(frame_t *victim);

/**
 * Function to page in frames from disk
 * @param user_process the pointer to the PCB of the process that faulted
 * @param vaddr the fault address passed in by the vm fault handler
 * 
 * @return 0 on success, 1 if the page was never paged out, -1 on error
 */
int clock_try_page_in(user_process_t *user_process, seL4_Word vaddr);