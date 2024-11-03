#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>

#include <sos.h>
int main (void)
{
    int fd = sos_open("chirag.txt", O_RDWR);
    assert(fd > 2);
    int err = sos_write(fd, "ThisIsAnExampleStringForWhichIAmAddingAUniqueIdThatShowsIWroteThis:Malenia\n", 76);
    assert(err == 76);
    int res = sos_close(fd);
    assert(!res);
}