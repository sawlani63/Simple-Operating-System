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

/*#include <stdio.h>
#include <sel4/sel4.h>
#include <sos.h>


static void thread_block(void)
{

    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);

    seL4_SetMR(0, 1);

    seL4_Call(SOS_IPC_EP_CAP, tag);

}

int main(void)
{
    do {
        fputs("task:\tHello world, I'm\tconsole_test!\n", stdout);
        thread_block();
        // sleep(1);    // Implement this as a syscall in the future
    } while (1);

    return 0;
}*/

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <utils/time.h>
#include <syscalls.h>
/* Your OS header file */
#include <sos.h>

#include "benchmark.h"

#define SMALL_BUF_SZ 2
#define MEDIUM_BUF_SZ 256

char test_str[] = "Basic test string for read/write\n";
char small_buf[SMALL_BUF_SZ];

int test_buffers(int console_fd) {
   /* test a small string from the code segment */
   int result = sos_write(console_fd, test_str, strlen(test_str));
   assert(result == strlen(test_str));

   /* try sleeping */
   for (int i = 0; i < 5; i++) {
       int64_t prev_seconds = sos_time_stamp();
       sos_usleep(1000000);
       int64_t next_seconds = sos_time_stamp();
       assert(next_seconds > prev_seconds);
       printf("Tick, diff: %lu (%lu, %lu)\n", next_seconds - prev_seconds, prev_seconds, next_seconds);
   }
}

int main(void) {
    test_buffers(1);
    return 0;
}