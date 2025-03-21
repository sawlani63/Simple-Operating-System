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
    if (path == NULL) {
        return -1;
    }
    
    seL4_SetMR(0, SYSCALL_SOS_OPEN);
    seL4_SetMR(1, (seL4_Word) path);
    seL4_SetMR(2, strlen(path));
    seL4_SetMR(3, mode);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}

int sos_close(int file)
{
    seL4_SetMR(0, SYSCALL_SOS_CLOSE);
    seL4_SetMR(1, file);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
    return seL4_GetMR(0);
}

int sos_read(int file, char *buf, size_t nbyte)
{
    if (buf == NULL) {
        return -1;
    }

    seL4_SetMR(0, SYSCALL_SOS_READ);
    seL4_SetMR(1, file);
    seL4_SetMR(2, (seL4_Word) buf);
    seL4_SetMR(3, nbyte);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}

int sos_write(int file, const char *buf, size_t nbyte)
{
    if (buf == NULL) {
        return -1;
    }

    seL4_SetMR(0, SYSCALL_SOS_WRITE);
    seL4_SetMR(1, file);
    seL4_SetMR(2, (seL4_Word) buf);
    seL4_SetMR(3, nbyte);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}

int sos_getdirent(int pos, char *name, size_t nbyte)
{
    seL4_SetMR(0, SYSCALL_SOS_GETDIRENT);
    seL4_SetMR(1, pos);
    seL4_SetMR(2, (seL4_Word) name);
    seL4_SetMR(3, nbyte);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}

int sos_stat(const char *path, sos_stat_t *buf)
{
    if (path == NULL || buf == NULL) {
        return -1;
    }

    seL4_SetMR(0, SYSCALL_SOS_STAT);
    seL4_SetMR(1, (seL4_Word) path);
    seL4_SetMR(2, (seL4_Word) buf);
    seL4_SetMR(3, strlen(path));
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}

pid_t sos_process_create(const char *path)
{
    if (path == NULL) {
        return -1;
    }

    seL4_SetMR(0, SYSCALL_PROC_CREATE);
    seL4_SetMR(1, (seL4_Word) path);
    seL4_SetMR(2, strlen(path));
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 3));
    return seL4_GetMR(0);
}

int sos_process_delete(pid_t pid)
{
    seL4_SetMR(0, SYSCALL_PROC_DELETE);
    seL4_SetMR(1, (seL4_Word) pid);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
    return seL4_GetMR(0);
}

pid_t sos_my_id(void)
{
    seL4_SetMR(0, SYSCALL_PROC_GETID);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 1));
    return seL4_GetMR(0);
}

int sos_process_status(sos_process_t *processes, unsigned max)
{
    if (!max) {
        return -1;
    }
    seL4_SetMR(0, SYSCALL_PROC_STATUS);
    seL4_SetMR(1, (seL4_Word) processes);
    seL4_SetMR(2, max);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 3));
    return seL4_GetMR(0);
}

pid_t sos_process_wait(pid_t pid)
{
    seL4_SetMR(0, SYSCALL_PROC_WAIT);
    seL4_SetMR(1, (pid_t) pid);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
    return seL4_GetMR(0);
}

void sos_usleep(int msec)
{
    if (msec < 0) {
        return;
    }
    /* Request the timer driver to register a timer with msec delay */
    seL4_SetMR(0, timer_RegisterTimer);
    seL4_SetMR(1, msec);
    seL4_Send(TIMER_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 2));
    /* Wait on the timer driver to signal the notification to wake up */
    seL4_Wait(TIMER_NTFN, 0);
}

int64_t sos_time_stamp(void)
{
    seL4_SetMR(0, timer_MicroTimestamp);
    seL4_Call(TIMER_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 1));
    return seL4_GetMR(0);
}

/*************************************************************************/
/*                                   */
/* Optional (bonus) system calls                     */
/*                                   */
/*************************************************************************/

int sos_share_vm(void *adr, size_t size, int writable) 
{
    seL4_SetMR(0, SYSCALL_SOS_SHARE_VM);
    seL4_SetMR(1, (seL4_Word) adr);
    seL4_SetMR(2, (seL4_Word) size);
    seL4_SetMR(3, (seL4_Word) writable);
    seL4_Call(SOS_IPC_EP_CAP, seL4_MessageInfo_new(0, 0, 0, 4));
    return seL4_GetMR(0);
}