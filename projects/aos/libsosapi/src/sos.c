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
#include <stdarg.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sos.h>

#include <sel4/sel4.h>

#define STDIN_FD 0
#define STDOUT_FD 1
#define STDERR_FD 2

static size_t sos_debug_print(const void *vData, size_t count)
{
#ifdef CONFIG_DEBUG_BUILD
    size_t i;
    const char *realdata = vData;
    for (i = 0; i < count; i++) {
        seL4_DebugPutChar(realdata[i]);
    }
#endif
    return count;
}

int sos_open(const char *path, fmode_t mode)
{
    int len = strlen(path);
    if (len + 3 > seL4_MsgMaxLength) {
        len = seL4_MsgMaxLength - 3;
    }

    seL4_SetMR(0, SYSCALL_SOS_OPEN);
    seL4_SetMR(1, mode);
    seL4_SetMR(2, len);
    for (int i = 0; i < len; i++) {
        seL4_SetMR(i + 3, path[i]);
    }
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, len + 3));
    return seL4_GetMR(0);
}

int sos_close(int file)
{
    assert(!"You need to implement this");
    return -1;
}

int sos_read(int file, char *buf, size_t nbyte)
{
    for (int i = 0; i < nbyte; i++) {
        seL4_SetMR(0, SYSCALL_SOS_READ);
        seL4_SetMR(1, file);
        seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 1));
        char recv = seL4_GetMR(0);
        if (recv == -1) {
            return -1;
        }
        buf[i] = recv;
    }
    return nbyte;
}

int sos_write(int file, const char *buf, size_t nbyte)
{
    /* NOTE: We only need to send one byte at a time as this is handled by
     * __stdio_write + sys_writev where __stdio_write takes the entire buffer
     * and continuously calls sys_writev until the entire length is written. */
    for (int i = 0; i < nbyte; i++) {
        seL4_SetMR(0, SYSCALL_SOS_WRITE);
        seL4_SetMR(1, file);
        seL4_SetMR(2, buf[i]);
        seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 3));
        if (seL4_GetMR(0) == -1) {
            return -1;
        }
    }
    return nbyte;
}

int sos_getdirent(int pos, char *name, size_t nbyte)
{
    assert(!"You need to implement this");
    return -1;
}

int sos_stat(const char *path, sos_stat_t *buf)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_process_create(const char *path)
{
    assert(!"You need to implement this");
    return -1;
}

int sos_process_delete(pid_t pid)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_my_id(void)
{
    assert(!"You need to implement this");
    return -1;

}

int sos_process_status(sos_process_t *processes, unsigned max)
{
    assert(!"You need to implement this");
    return -1;
}

pid_t sos_process_wait(pid_t pid)
{
    assert(!"You need to implement this");
    return -1;

}

void sos_usleep(int msec)
{
    seL4_SetMR(0, SYSCALL_SOS_USLEEP);
    seL4_SetMR(1, msec);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
}

int64_t sos_time_stamp(void)
{
    /* Set the first message register to the sos_time_stamp syscall number */
    seL4_SetMR(0, SYSCALL_SOS_TIME_STAMP);
    /* Invokes the SOS endpoint for the IPC protocol to request a response and block until one is received */
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 1));
    /* Return the response received from SOS */
    return seL4_GetMR(0);
}
