#pragma once

#include <stdlib.h>
#include <cspace/cspace.h>
#include <aos/vsyscall.h>

#include "process.h"

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

#define SYSCALL_SOS_OPEN SYS_openat
#define SYSCALL_SOS_CLOSE SYS_close
#define SYSCALL_SOS_READ SYS_readv
#define SYSCALL_SOS_WRITE SYS_writev
#define SYSCALL_SOS_USLEEP SYS_nanosleep
#define SYSCALL_SOS_TIME_STAMP SYS_clock_gettime
#define SYSCALL_SOS_GETDIRENT SYS_getdents64
#define SYSCALL_SOS_STAT SYS_statfs
#define SYSCALL_SOS_SHARE_VM 1

#define SYSCALL_SYS_BRK SYS_brk
#define SYSCALL_SYS_MMAP SYS_mmap
#define SYSCALL_SYS_MUNMAP SYS_munmap

/* SOS system calls */
void syscall_sos_open(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_close(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_read(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_write(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_usleep(seL4_MessageInfo_t *reply_msg, UNUSED seL4_Word badge);
void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg);
void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sos_share_vm(seL4_MessageInfo_t *reply_msg, seL4_Word badge);

/* SYS system calls */
void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sys_mmap(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_sys_munmap(seL4_MessageInfo_t *reply_msg, seL4_Word badge);

void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number);

void init_semaphores(void);
int netcon_send(open_file *file, char *data, UNUSED uint64_t offset, uint64_t len, void *callback, void *args);
int perform_cpy(user_process_t user_process, size_t nbyte, uintptr_t vaddr, bool data_to_buff, void *buff);