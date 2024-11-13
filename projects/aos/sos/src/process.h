#pragma once

#include <stdlib.h>
#include <cspace/cspace.h>
#include <sync/bin_sem.h>
#include <aos/vsyscall.h>

#include "fs.h"
#include "addrspace.h"
#include "threads.h"

/* Number of concurrently running processes supported */
#define NUM_PROC 32

#define N_NAME 32

// Could not find constants for the others so just set to numbers around sys_getpid
#define SYSCALL_PROC_CREATE 170 // maybe use fork number
#define SYSCALL_PROC_DELETE SYS_kill
#define SYSCALL_PROC_GETID SYS_getpid
#define SYSCALL_PROC_STATUS 173
#define SYSCALL_PROC_WAIT SYS_waitid

typedef size_t frame_ref_t;

typedef struct {
    pid_t pid;
    char *app_name;
    unsigned size;
    unsigned stime;

    addrspace_t *addrspace;
    fdt *fdt;
    sos_thread_t *handler_thread;

    sync_bin_sem_t *handler_busy_sem;
    seL4_CPtr handler_busy_cptr;
    ut_t *handler_busy_ut;

    seL4_CPtr ep;
    ut_t *ep_ut;
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_CPtr wake;
    ut_t *wake_ut;

    seL4_CPtr ep_slot;
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

int init_proc();
user_process_t get_process(pid_t pid);
int start_process(char *app_name, thread_main_f *func);
void syscall_proc_create(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_delete(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_getid(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_status(seL4_MessageInfo_t *reply_msg, seL4_Word badge);
void syscall_proc_wait(seL4_MessageInfo_t *reply_msg, seL4_Word badge);