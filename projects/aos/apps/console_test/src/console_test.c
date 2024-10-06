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
#include <fcntl.h>

#include <sel4/sel4.h>
#include <sos.h>

#include <utils/page.h>

#define NBLOCKS 9
#define NPAGES_PER_BLOCK 28
#define TEST_ADDRESS 0x1000000000

/* called from pt_test */
static void do_pt_test(char **buf) {
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

static void pt_test(void) {
    /* need a decent sized stack */
    char buf1[NBLOCKS][NPAGES_PER_BLOCK * PAGE_SIZE_4K];
    char *buf1_ptrs[NBLOCKS];
    char *buf2[NBLOCKS];

    /* check the stack is above phys mem */
    for (int b = 0; b < NBLOCKS; b++) {
        buf1_ptrs[b] = buf1[b];
    }

    assert((void *) buf1 > (void *) TEST_ADDRESS);
    fputs("Passed initial assert\n", stdout);

    /* stack test */
    do_pt_test(buf1_ptrs);

    fputs("Passed stack test\n", stdout);

    /* heap test */
    for (int b = 0; b < NBLOCKS; b++) {
        buf2[b] = malloc(NPAGES_PER_BLOCK * PAGE_SIZE_4K);
        assert(buf2[b]);
    }
    do_pt_test(buf2);
    for (int b = 0; b < NBLOCKS; b++) {
        free(buf2[b]);
    }
    fputs("Passed heap test\n", stdout);
}

static void recursive_stack_test(int counter) {
    char **arr = malloc(NBLOCKS * sizeof(char *));
    for (int i = 0; i < NBLOCKS; i++) {
        arr[i] = malloc(NPAGES_PER_BLOCK * PAGE_SIZE_4K);
    }
    if (counter == 1000) {
        return;
    }
    recursive_stack_test(counter + 1);
}

#define SMALL_BUF_SZ 2
#define MEDIUM_BUF_SZ 5

char test_str[] = "Basic test string for read/write\n";
char small_buf[SMALL_BUF_SZ];

int test_buffers(int console_fd) {
    /* test a small string from the code segment */
    int result = sos_write(console_fd, test_str, strlen(test_str));
    assert(result == strlen(test_str));

    /* test reading to a small buffer */
    result = sos_read(console_fd, small_buf, SMALL_BUF_SZ);
    /* make sure you type in at least SMALL_BUF_SZ */
    assert(result == SMALL_BUF_SZ);

    /* test reading into a large on-stack buffer */
    char stack_buf[MEDIUM_BUF_SZ];
    /* for this test you'll need to paste a lot of data into
      the console, without newlines */

    result = sos_read(console_fd, stack_buf, MEDIUM_BUF_SZ);
    assert(result == MEDIUM_BUF_SZ);

    result = sos_write(console_fd, stack_buf, MEDIUM_BUF_SZ);
    assert(result == MEDIUM_BUF_SZ);

    /* try sleeping */
    for (int i = 0; i < 5; i++) {
        uint64_t prev_seconds = sos_time_stamp();
        sos_usleep(1000000);
        uint64_t next_seconds = sos_time_stamp();
        assert(next_seconds > prev_seconds);
        fputs("Tick\n", stdout);
    }
}

int test_stack_write(int console_fd) {
   /* test a small string from the code segment */
   char rip[45];
   for (int i = 0; i < 44; i++) {
    rip[i] = 'a';
   }
   rip[44] = '\0';
   int result = sos_write(console_fd, rip, strlen(rip));    
   assert(result == strlen(rip));
   fputs("\nPassed large write test\n", stdout);
}

int main(void)
{
    int fd = sos_open("console", O_RDWR);
    assert(fd > 2);
    int fail = sos_open("console", O_RDONLY);
    assert(fail == -1);
    fail = sos_open("console", O_RDWR);
    assert(fail == -1);
    int res = sos_close(fd);
    assert(!res);
    fd = sos_open("console", O_RDWR);
    assert(fd > 2);
    printf("Passed open/close test\n");
    
    pt_test();
    test_stack_write(fd);

    test_buffers(fd);
    fputs("Passed read/write buffer test\n", stdout);

    // recursive_stack_test(0);
    // fputs("Passed recursive stack test\n", stdout);
}