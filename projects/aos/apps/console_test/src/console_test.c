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
#include <sys/mman.h>

#define NBLOCKS 9
#define NPAGES_PER_BLOCK 28
#define TEST_ADDRESS 0x100000000

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

    /* test reading into a large on-heap buffer */
    char *heap_buf = malloc(MEDIUM_BUF_SZ);
    /* for this test you'll need to paste a lot of data into
      the console, without newlines */

    result = sos_read(console_fd, heap_buf, MEDIUM_BUF_SZ);
    assert(result == MEDIUM_BUF_SZ);

    result = sos_write(console_fd, heap_buf, MEDIUM_BUF_SZ);
    assert(result == MEDIUM_BUF_SZ);

    /* try sleeping */
    for (int i = 0; i < 5; i++) {
        uint64_t prev_seconds = sos_time_stamp();
        sos_usleep(1000000);
        uint64_t next_seconds = sos_time_stamp();
        assert(next_seconds > prev_seconds);
        printf("Tick\n");
    }
}

int test_nfs() {
    /* IMPORTANT: NEED TO CHANGE FILE EVERY TIME
     * WE RERUN TEST SINCE NFS IS PERSISTENT STORAGE*/
    char *file = "Pikachu10.txt";

    printf("%d", sos_time_stamp());
    int fd = sos_open(file, O_RDWR);
    assert(fd > 2);

    sos_stat_t stat;
    sos_stat(file, &stat);
    printf("From stat - type: %d, mode: %d, size: %u, atime: %ld, ctime: %ld\n",
           stat.st_type, stat.st_fmode, stat.st_size, stat.st_atime, stat.st_ctime);
    printf("%d", sos_time_stamp());

    char *buffer = calloc(81, sizeof(char));

    /* should be garbage / nothing */
    // int result = sos_read(fd, buffer, MEDIUM_BUF_SZ);
    // assert(!result);
    // printf("Garbage Buffer: %s\n", buffer);

    /* test a small string from the code segment */
    int result = sos_write(fd, "WritingASomewhatLongerStringToTestI/OOverlappingActuallyWorksAsIntendedForOnce\n", 80);
    assert(result == 80);
    
    /* Close and reopen the file so we reset the offset. */
    int res = sos_close(fd);
    assert(!res);
    fd = sos_open(file, O_RDWR);
    assert(fd > 2);

    /* test reading to a small buffer */
    result = sos_read(fd, buffer, 80);
    assert(result == 80);
    printf("\nbuffer: %s\n", buffer);
    assert(!strcmp(buffer, "WritingASomewhatLongerStringToTestI/OOverlappingActuallyWorksAsIntendedForOnce\n"));

    sos_stat(file, &stat);
    printf("From stat - type: %d, mode: %d, size: %u, atime: %ld, ctime: %ld\n",
           stat.st_type, stat.st_fmode, stat.st_size, stat.st_atime, stat.st_ctime);
}

int test_stack_write(int console_fd) {
   char rip[1000];
   memset(rip, 'a', 999);
   rip[999] = '\0';
   int result = sos_write(console_fd, rip, strlen(rip));    
   assert(result == strlen(rip));
   printf("\nPassed large write test\n");
}

#define SIZE_ALIGN (4*sizeof(size_t))
#define MMAP_THRESHOLD (0x1c00*SIZE_ALIGN)

int mmap_test_core(int size) {
    char *buf = mmap(0, size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    char *buf1 = malloc(size);

    /* Set */
    for (int b = 0; b < size / PAGE_SIZE_4K; b+=PAGE_SIZE_4K) {
        buf[b] = b;
        buf1[b] = b;
    }

    /* Check */
    for (int b = 0; b < size / PAGE_SIZE_4K; b+=PAGE_SIZE_4K) {
        assert(buf[b] == b);
        assert(buf1[b] == b);
    }

    munmap(buf, size);
    free(buf1);
}

int mmap_test() {
    int size = MMAP_THRESHOLD * 2;
    mmap_test_core(size);
    printf("Passed mmap test\n");
}

int main(void)
{
    // int fd = sos_open("console", O_RDWR);
    // assert(fd == 0);
    // int fail = sos_open("console", O_RDONLY);
    // assert(fail == -1);
    // fail = sos_open("console", O_RDWR);
    // assert(fail == -1);
    // int res = sos_close(fd);
    // assert(!res);
    // fd = sos_open("console", O_RDWR);
    // assert(fd == 0);
    // printf("Passed open/close test\n");

    // test_nfs();
    // printf("Passed nfs test\n");
    
    // pt_test();
    // mmap_test();
    // //test_stack_write(fd);

    // test_buffers(fd);
    // printf("Passed read/write buffer test\n");

    /*for (int i = 0; i < 50; i++) {
        int pid = sos_process_create("console_test_2");
        if (pid == -1) {
            break;
        }
        int res = sos_process_delete(pid);
        assert(res == 0);
        printf("Passed %d\n", i + 1);
    }
    printf("Passed process delete test\n");

    int pid = sos_process_create("console_test_2");
    int pid2 = sos_my_id();
    assert(pid2 == 0);
    printf("Current pid %d\n", pid2);
    sos_process_t *pinfo = malloc(16 * sizeof(sos_process_t));
    int num = sos_process_status(pinfo, 3);
    assert(num == 2);
    for (int i = 0; i < num; i++) {
        printf("From process status: pid - %d, size - %d, stime - %d, app_name - %s\n", pinfo[i].pid, pinfo[i].size, pinfo[i].stime, pinfo[i].command);
    }
    num = sos_process_status(pinfo, 1);
    assert(num == 1);
    for (int i = 0; i < num; i++) {
        printf("From process status: pid - %d, size - %d, stime - %d, app_name - %s\n", pinfo[i].pid, pinfo[i].size, pinfo[i].stime, pinfo[i].command);
    }*/

    #define SHARED_PAGE_SIZE 0x1000
    char *shared_buffer = (char *) 0x1000;

    int res = sos_share_vm(shared_buffer, SHARED_PAGE_SIZE, 1);
    memset(shared_buffer, 0, SHARED_PAGE_SIZE);
    strncpy(shared_buffer, "Hello World!", SHARED_PAGE_SIZE - 1);
    assert(!strcmp(shared_buffer, "Hello World!"));

    int pid = sos_process_create("console_test_2");
    sos_process_wait(pid);
    
    assert(!strcmp(shared_buffer, "Goodbye World!"));
    printf("Passed shared memory test!\n");
}