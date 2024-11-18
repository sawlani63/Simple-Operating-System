#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include <sos.h>
int main (void)
{
    #define SHARED_ADDRESS   0x1000
    #define SHARED_PAGE_SIZE 0x1000
    int res = sos_share_vm(SHARED_ADDRESS, SHARED_PAGE_SIZE, 1);
    assert(!strcmp(SHARED_ADDRESS, "Hello World!"));
    strncpy(SHARED_ADDRESS, "Goodbye World!", SHARED_PAGE_SIZE - 1);
}