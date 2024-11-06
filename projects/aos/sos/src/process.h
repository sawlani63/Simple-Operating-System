#pragma once

#include <autoconf.h>
#include <utils/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <cspace/cspace.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>

#include <clock/clock.h>
#include <cpio/cpio.h>
#include <elf/elf.h>
#include <networkconsole/networkconsole.h>

#include <sel4runtime.h>
#include <sel4runtime/auxv.h>

#include "bootstrap.h"
#include "irq.h"
#include "network.h"
#include "frame_table.h"
#include "drivers/uart.h"
#include "ut.h"
#include "vmem_layout.h"
#include "mapping.h"
#include "elfload.h"
#include "syscalls.h"
#include "tests.h"
#include "utils.h"
#include "threads.h"
#include <sos/gen_config.h>
#ifdef CONFIG_SOS_GDB_ENABLED
#include "debugger.h"
#endif /* CONFIG_SOS_GDB_ENABLED */

#include <aos/vsyscall.h>
#include "thread_pool.h"
#include "addrspace.h"

/* File System */
#include "console.h"
#include "nfs.h"
#include "fs.h"

/* Number of concurrently running processes supported */
#define NUM_PROC 16

#define N_NAME 32

// Could not find constants for the others so just set to numbers around sys_getpid
#define SYSCALL_PROC_CREATE 170
#define SYSCALL_PROC_DELETE 171
#define SYSCALL_PROC_GETID SYS_getpid
#define SYSCALL_PROC_STATUS 173
#define SYSCALL_PROC_WAIT 174

typedef struct user_process {
    pid_t pid;
    char *app_name;
    unsigned size;
    unsigned stime;

    addrspace_t *addrspace;
    fdt *fdt;
    sos_thread_t *handler_thread;

    seL4_CPtr ep;
    ut_t *ep_ut;

    seL4_CPtr slot;
    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    frame_ref_t ipc_buffer_frame;
    seL4_CPtr ipc_buffer;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    frame_ref_t stack_frame;
    seL4_CPtr stack;
} user_process_t;

typedef struct {
    pid_t     pid;
    unsigned  size;            /* in pages */
    unsigned  stime;           /* start time in msec since booting */
    char      command[N_NAME]; /* Name of exectuable */
} sos_process_t;

typedef int pid_t;

void syscall_ipc_init();
int start_process(char *app_name, thread_main_f *func);
void syscall_proc_create(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_delete(seL4_MessageInfo_t *reply_msg);
void syscall_proc_getid(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_status(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_wait(seL4_MessageInfo_t *reply_msg, seL4_Word badge);