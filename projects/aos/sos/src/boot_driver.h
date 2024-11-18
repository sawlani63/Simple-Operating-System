#pragma once

#include <stdlib.h>
#include <cspace/cspace.h>
#include <sync/bin_sem.h>
#include <aos/vsyscall.h>

#include "addrspace.h"

#include "process.h"

#define TIMER_DEVICE "clock_driver"

enum clock_driver_requests {
    timer_RegisterTimer = 0,
    timer_MicroTimestamp = 1,
    timer_MilliTimestamp = 2
};
int init_driver_irq_handling(seL4_IRQControl irq_control, seL4_Word irq, int level, user_process_t user_process, seL4_CPtr ntfn);