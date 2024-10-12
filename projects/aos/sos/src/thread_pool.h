#pragma once

#include <cspace/cspace.h>
#include "ut.h"

#define NUM_THREADS 2
#define QUEUE_SIZE 4
#define NUM_MSG_REGISTERS 4

struct task {
    ut_t *reply_ut;
    seL4_CPtr reply;
    seL4_Word msg[NUM_MSG_REGISTERS];
};

void submit_task(struct task task);

void start_sos_worker_thread(void *arg);

void initialise_thread_pool(void (*input_func)(void *arg));