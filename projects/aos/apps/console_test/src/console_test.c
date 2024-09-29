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
#include <assert.h>

#include <sel4/sel4.h>
#include <sos.h>

// Block a thread forever
// we do this by making an unimplemented system call.
static void thread_block(void)
{
    /* construct some info about the IPC message console_test will send
     * to sos -- it's 1 word long */
    seL4_MessageInfo_t tag = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the first word in the message to 1 */
    seL4_SetMR(0, 1);
    /* Now send the ipc -- call will send the ipc, then block until a reply
     * message is received */
    seL4_Call(SOS_IPC_EP_CAP, tag);
    /* Currently SOS does not reply -- so we never come back here */
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

//    /* try sleeping */
//    for (int i = 0; i < 5; i++) {
//        time_t prev_seconds = time(NULL);
//        second_sleep(1);
//        time_t next_seconds = time(NULL);
//        assert(next_seconds > prev_seconds);
//        printf("Tick\n");
//    }
}

int main(void)
{
    do {
        test_buffers(1);
        fputs("task:\tHello world, I'm\tconsole_test!\n", stdout);
        thread_block();
        // sleep(1);    // Implement this as a syscall in the future
    } while (1);

    return 0;
}
