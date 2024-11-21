#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include <sos.h>
int main (void)
{
    /*#define SHARED_ADDRESS   0x1000
    #define SHARED_PAGE_SIZE 0x1000
    int res = sos_share_vm(SHARED_ADDRESS, SHARED_PAGE_SIZE, 1);
    assert(!strcmp(SHARED_ADDRESS, "Hello World!"));
    strncpy(SHARED_ADDRESS, "Goodbye World!", SHARED_PAGE_SIZE - 1);*/

    for (int i = 0; i < 5; i++) {
        uint64_t prev_seconds = sos_time_stamp();
        sos_usleep(1000000);
        uint64_t next_seconds = sos_time_stamp();
        assert(next_seconds - prev_seconds < 1001000);
        printf("Tick %d\n", next_seconds - prev_seconds);
    }
    printf("Passed!\n");
}