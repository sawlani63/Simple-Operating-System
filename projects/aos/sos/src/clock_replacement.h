#include "addrspace.h"

/**
 * Identifies a candidate to page out, and writes it into the paging file on the nfs.
 * The corresponding frame is then unmapped from the hardware page table.
 * @return 0 on success and 1 on failure
 */
int clock_page_out();

/**
 * Adds a page in the page table to the clock circular buffer.
 * @param vaddr The virtual address we are adding to our clock cicular buffer
 * @return 0 on success and 1 on failure
 */
int clock_add_page(seL4_Word vaddr);