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
#include <stdlib.h>
#include <stdint.h>
#include <clock/clock.h>
#include <clock/timestamp.h>

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"

#define MIN_HEAP_SIZE 32
#define MAX_TIMEOUT 65535 * 100
#define COMPARE_UNSIGNED(a, b) ((a > b) - (a < b))
#define MINHEAP_TIME_COMPARATOR(x, y) COMPARE_UNSIGNED(y.time_expired, x.time_expired)
#define MINHEAP_ID_COMPARATOR(x, y) COMPARE_UNSIGNED(y.id, x.id)

static struct {
    volatile meson_timer_reg_t *regs;
} clock;

typedef struct {
    uint32_t id;
    uint64_t time_expired;
    timer_callback_t callback;
    void *data;
} timer_node;

int max_timers = MIN_HEAP_SIZE;
timer_node *min_heap = NULL;
int first_free = 0;
uint32_t curr_id = 0;

static int remove_from_heap(int index, uint32_t id);
static void reset_timer_a();
static int invoke_callbacks();

int start_timer(unsigned char *timer_vaddr)
{
    /* If the driver is already initialised we stop the timer and restart.*/
    stop_timer();

    /* Set the clock registers to the base + reg offset and start timer E. */
    clock.regs = (meson_timer_reg_t *) (timer_vaddr + TIMER_REG_START);

    /* Allocate the min heap for keeping track of timers and configure timer A. */
    min_heap = malloc(sizeof(timer_node) * max_timers);
    configure_timeout(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_100_US, 0);

    return min_heap == NULL ? CLOCK_R_UINT : CLOCK_R_OK;
}

timestamp_t get_time(void)
{
    return read_timestamp(clock.regs);
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{
    /* Clamp timer A in case a user specifies too large a value for uint16_t. */
    if (delay > MAX_TIMEOUT) {
        delay = MAX_TIMEOUT;
    }
    uint64_t time_expired = (read_timestamp(clock.regs) + delay) / 100;
    if (SGLIB_HEAP_IS_FULL(first_free, max_timers)) {
        /* Reallocate memory for the heap, doubling its size. */
        timer_node *new_min_heap = realloc(min_heap, sizeof(timer_node) * max_timers * 2);
        if (new_min_heap == NULL) {
            return 0;
        }
        max_timers *= 2;
        min_heap = new_min_heap;
    } else if (SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)
        || SGLIB_HEAP_GET_MIN(min_heap).time_expired > time_expired) {
        write_timeout(clock.regs, MESON_TIMER_A, delay / 100);
    }
    
    /* Create a new timer node with the specified fields and add it to the heap. */
    timer_node node = {++curr_id, time_expired, callback, data};
    SGLIB_HEAP_ADD(timer_node, min_heap, node, first_free, max_timers, MINHEAP_TIME_COMPARATOR);
    return curr_id;
}

int remove_timer(uint32_t id)
{
    /* Create a dud sample node with the id we are searching for to find the real node's index. */
    int index;
    timer_node node = {id, 0, NULL, NULL};
    SGLIB_HEAP_FIND(timer_node, min_heap, first_free, MINHEAP_ID_COMPARATOR, node, index);
    /* If we found the node, remove it from the heap. If the node was at the head, reset timer A. */
    if (index == -1 || remove_from_heap(index, id)) {
        return CLOCK_R_FAIL;
    } else if (index == 0) {
        reset_timer_a();
    }
    return CLOCK_R_OK;
}

int timer_irq(void *data, seL4_Word irq, seL4_IRQHandler irq_handler)
{
    /* May want to change later, not sure if CLOCK_R_OK is best to return here. */
    if (SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)) {
        seL4_IRQHandler_Ack(irq_handler);
        return CLOCK_R_OK;
    }

    /* Run the necessary callbacks, reset timer A, and acknowledge that the IRQ has been handled. */
    if (invoke_callbacks()) {
        return CLOCK_R_FAIL;
    }
    reset_timer_a();
    seL4_IRQHandler_Ack(irq_handler);
    return CLOCK_R_OK;
}

int stop_timer(void)
{
    /* If the driver is not initialized, return an error */
    if (min_heap == NULL) {
        return CLOCK_R_FAIL;
    }
    /* Stop the timer from producing further interrupts and free the min heap. */
    configure_timeout(clock.regs, MESON_TIMER_A, false, false, TIMEOUT_TIMEBASE_1_MS, 0);
    free(min_heap);

    return CLOCK_R_OK;
}

static int remove_from_heap(int index, uint32_t id) {
    /* This is purely for optimisation since REMOVE does work that isn't necessary for popping. */
    if (index == 0) {
        SGLIB_HEAP_DELETE(timer_node, min_heap, first_free, max_timers, MINHEAP_TIME_COMPARATOR);
    } else {
        SGLIB_HEAP_REMOVE(timer_node, min_heap, index, first_free, MINHEAP_TIME_COMPARATOR);
    }
    
    /* If after removing our heap is mostly empty, realloc its size to shrink it in half. */
    if (max_timers > MIN_HEAP_SIZE && first_free < max_timers / 2) {
        timer_node *new_min_heap = realloc(min_heap, sizeof(timer_node) * max_timers / 2);
        if (new_min_heap == NULL) {
            return 1;
        }
        max_timers /= 2;
        min_heap = new_min_heap;
    }
    return 0;
}

static void reset_timer_a()
{
    /* If the heap isn't empty, set timer A to the next node's delay. */
    if (!SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)) {
        uint64_t new = SGLIB_HEAP_GET_MIN(min_heap).time_expired - read_timestamp(clock.regs) / 100;
        write_timeout(clock.regs, MESON_TIMER_A, new);
    }
}

static int invoke_callbacks()
{
    /* Keep popping from the heap all timers that have expired and run their callback functions. */
    timer_node first_elem;
    do {
        first_elem = SGLIB_HEAP_GET_MIN(min_heap);
        first_elem.callback(first_elem.id, first_elem.data);
        if (remove_from_heap(0, first_elem.id)) {
            return 1;
        }
    } while (!SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)
            && first_elem.time_expired == SGLIB_HEAP_GET_MIN(min_heap).time_expired);
    return 0;
}