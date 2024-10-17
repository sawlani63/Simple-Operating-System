#include "clock_replacement.h"

#define GET_PAGE(pt, vaddr) pt[(vaddr >> 39) & MASK(9)].l2[(vaddr >> 30) & MASK(9)].l3[(vaddr >> 21) & MASK(9)].l4[(vaddr >> 12) & MASK(9)].page

/* 2^19 is the entire frame table size, meaning we can
   cover every page with 2^19 * 8 bytes = 4MB of memory. */
#ifdef CONFIG_SOS_FRAME_LIMIT
    #define BUFFER_SIZE (CONFIG_SOS_FRAME_LIMIT != 0ul ? CONFIG_SOS_FRAME_LIMIT : BIT(19))
#else
    #define BUFFER_SIZE BIT(19)
#endif

seL4_Word circular_buffer[BUFFER_SIZE];
/* The clock hand pointing to the current position in the circular buffer */
size_t clock_hand = 0;
size_t curr_size = 0;

/**
 * Identifies a candidate to page out, and writes it into the paging file on the nfs.
 * The corresponding frame is then unmapped from the hardware page table.
 * @return 0 on success and 1 on failure
 */
static int clock_page_out() {
    return 0;
}   

int clock_add_page(seL4_Word vaddr) {
    if (curr_size == BUFFER_SIZE) {
        if (clock_page_out()) {
            return 1;
        }
    } else {
        curr_size++;
    }

    circular_buffer[clock_hand] = vaddr;
    clock_hand = (clock_hand + 1) % BUFFER_SIZE;

    return 0;
}