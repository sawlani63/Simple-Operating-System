#pragma once

#include "frame_table.h"
#include "process.h"

/**
 * Initialises the bitmap / swap map.
 */
void init_bitmap();

/**
 * Marks a block or frame in the page file as free.
 * @param vaddr The block number associated with a frame.
 */
void mark_block_free(uint32_t block_num);

int clock_try_page_in(user_process_t *user_process, seL4_Word vaddr);

frame_t *clock_choose_victim(frame_ref_t clock_hand, frame_ref_t first);

int clock_page_out(frame_t *victim);

extern sync_bin_sem_t *data_sem;