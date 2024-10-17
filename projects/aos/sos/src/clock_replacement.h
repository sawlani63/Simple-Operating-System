#include "addrspace.h"

/**
 * Adds a page in the page table to the clock circular buffer.
 * @param vaddr The virtual address we are adding to our clock cicular buffer
 * @return 0 on success and 1 on failure
 */
int clock_add_page(seL4_Word vaddr);