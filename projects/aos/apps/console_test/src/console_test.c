/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
/****************************************************************************
 *
 *      $Id:  $
 *
 *      Description: Simple milestone 0 test.
 *
 *      Author:         Godfrey van der Linden
 *      Original Author:    Ben Leslie
 *
 ****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include <sel4/sel4.h>
#include <sos.h>

#include <utils/page.h>

#define NBLOCKS 9
#define NPAGES_PER_BLOCK 28
#define TEST_ADDRESS 0x8000000000

/* called from pt_test */
static void
do_pt_test(char **buf)
{
    int i;

    /* set */
    for (int b = 0; b < NBLOCKS; b++) {
        for (int p = 0; p < NPAGES_PER_BLOCK; p++) {
          buf[b][p * PAGE_SIZE_4K] = p;
        }
    }

    /* check */
    for (int b = 0; b < NBLOCKS; b++) {
        for (int p = 0; p < NPAGES_PER_BLOCK; p++) {
          assert(buf[b][p * PAGE_SIZE_4K] == p);
        }
    }
}

static void
pt_test( void )
{
    /* need a decent sized stack */
    char buf1[NBLOCKS][NPAGES_PER_BLOCK * PAGE_SIZE_4K];
    char *buf1_ptrs[NBLOCKS];
    char *buf2[NBLOCKS];

    /* check the stack is above phys mem */
    for (int b = 0; b < NBLOCKS; b++) {
        buf1_ptrs[b] = buf1[b];
    }

    assert((void *) buf1 > (void *) TEST_ADDRESS);
    printf("Passed initial assert\n");

    /* stack test */
    do_pt_test(buf1_ptrs);

    printf("Passed stack test\n");

    /* heap test */
    for (int b = 0; b < NBLOCKS; b++) {
        buf2[b] = malloc(NPAGES_PER_BLOCK * PAGE_SIZE_4K);
        assert(buf2[b]);
    }
    do_pt_test(buf2);
    for (int b = 0; b < NBLOCKS; b++) {
        free(buf2[b]);
    }
    printf("Passed heap test\n");
}

int main(void)
{
    do {
        fputs("task:\tHello world, I'm\tconsole_test!\n", stdout);
        pt_test();
        // sleep(1);    // Implement this as a syscall in the future
    } while(1);
}