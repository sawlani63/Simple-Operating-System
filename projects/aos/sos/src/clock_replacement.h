#include "addrspace.h"

/**
 * Replaces a page entry with a swapped entry in the page table and frees
 * the corresponding frame.
 * @return 0 on success and 1 on failure
 */
int clock_page_out();

/**
 * Adds a page in the page table to the clock circular buffer.
 * @param page The page table entry we are adding to our clock cicular buffer
 * @return 0 on success and 1 on failure
 */
int clock_add_page(pt_entry page);