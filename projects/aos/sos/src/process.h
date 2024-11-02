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

#define SYSCALL_PROC_CREATE 1000 //change later
#define SYSCALL_PROC_DELETE 1001 //change later
#define SYSCALL_PROC_GETID SYS_getpid
#define SYSCALL_PROC_STATUS 1002 //change later
#define SYSCALL_PROC_WAIT 1003 // change later

typedef int pid_t;

/* the one process we start */
typedef struct user_process {
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

    addrspace_t *addrspace;

    fdt *fdt;
    sos_thread_t *handler_thread;
    seL4_CPtr ep;
    pid_t pid;
} user_process_t;

int init_proc_obj();
bool start_process(char *app_name, thread_main_f *func);