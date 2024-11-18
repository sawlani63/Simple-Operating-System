#pragma once

#include <stdlib.h>
#include <cspace/cspace.h>
#include <sync/bin_sem.h>
#include <aos/vsyscall.h>

#include "addrspace.h"

#include "process.h"

#define TIMER_DEVICE "clock_driver"
#define TIMER_ID 50

/*enum clock_driver_requests {
    timer_RegisterTimer = 0,
    timer_MicroTimestamp = 1,
    timer_MilliTimestamp = 2
};*/

typedef int pid_t;

typedef struct {
    seL4_CPtr ep;
    ut_t *ep_ut;
    seL4_CPtr reply;
    ut_t *reply_ut;
    seL4_CPtr ntfn;
    ut_t *ntfn_ut;

    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    frame_ref_t ipc_buffer_frame;
    seL4_CPtr ipc_buffer;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    frame_ref_t stack_frame;
    seL4_CPtr stack;

    pid_t pid;
    addrspace_t *addrspace;
    cspace_t cspace;
} clock_process_t;

int start_clock_process();
int init_driver_irq_handling(seL4_IRQControl irq_control, seL4_Word irq, int level);