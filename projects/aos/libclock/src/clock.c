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
#include <clock/idstack.h>

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"

#define MAX_TIMEOUT 65535
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

int max_timers = 32;
timer_node *min_heap;
int first_free = 0;

static int remove_from_heap(int index, uint32_t id);
static void reset_timer_a();
static int invoke_callbacks();

int start_timer(unsigned char *timer_vaddr)
{
    /* If the driver is already initialised we stop the timer and restart.*/
    if (stop_timer() == CLOCK_R_FAIL) {
        return CLOCK_R_UINT;
    }

    /* Allocate memory for the clock registers, and identify the vaddr of the
     * timer registers. Each register is 32 bits, so we index like an array.*/
    clock.regs = malloc(sizeof(meson_timer_reg_t));
    if (clock.regs == NULL) {
        return CLOCK_R_UINT;
    }
    uint32_t *register_addresses = (uint32_t *) (timer_vaddr + TIMER_REG_START);

    /* Set the registers. */
    clock.regs->mux = register_addresses[0];
    clock.regs->timer_a = register_addresses[1];
    clock.regs->timer_e = register_addresses[5];
    clock.regs->timer_e_hi = register_addresses[6];

    /* We only need 10ms precision, so the default 1us timerbase resolution
     * is overkill and may waste system resources. We will set it to 1ms.*/
    configure_timeout(clock.regs, MESON_TIMER_A, true, false, TIMEOUT_TIMEBASE_1_MS, 0);
    configure_timestamp(clock.regs, TIMEOUT_TIMEBASE_1_US);

    /* Allocate the min heap and stack for keeping track of timers and ids. */
    min_heap = malloc(sizeof(timer_node) * max_timers);
    if (min_heap == NULL) {
        return CLOCK_R_UINT;
    }
    create_stack();

    return CLOCK_R_OK;
}

timestamp_t get_time(void)
{
    return read_timestamp(clock.regs);
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{
    if (delay > MAX_TIMEOUT) {
        delay = MAX_TIMEOUT;
    }
    uint64_t time_expired = (read_timestamp(clock.regs) + delay) / 1000;
    if (SGLIB_HEAP_IS_FULL(first_free, max_timers)) {
        timer_node *new_min_heap = realloc(min_heap, sizeof(timer_node) * max_timers * 2);
        if (new_min_heap == NULL) {
            return 0;
        }
        max_timers *= 2;
        min_heap = new_min_heap;
    } else if (SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)
        || SGLIB_HEAP_GET_MIN(min_heap).time_expired > time_expired) {
        write_timeout(clock.regs, MESON_TIMER_A, delay / 1000);
    }
    
    timer_node node = {new_id(), time_expired / 1000, callback, data};
    SGLIB_HEAP_ADD(timer_node, min_heap, node, first_free, max_timers, MINHEAP_TIME_COMPARATOR);
    return node.id;
}

int remove_timer(uint32_t id)
{
    int index;
    timer_node node = {id, 0, NULL, NULL};
    SGLIB_HEAP_FIND(timer_node, min_heap, first_free, MINHEAP_ID_COMPARATOR, node, index);
    if (index == -1 || remove_from_heap(index, id)) {
        return CLOCK_R_FAIL;
    } else if (index == 0) {
        reset_timer_a();
    }
    return CLOCK_R_OK;
}

int timer_irq(void *data, seL4_Word irq, seL4_IRQHandler irq_handler)
{
    if (invoke_callbacks()) {
        return CLOCK_R_FAIL;
    }
    reset_timer_a();
    /* Acknowledge that the IRQ has been handled. */
    seL4_IRQHandler_Ack(irq_handler);
    return CLOCK_R_OK;
}

int stop_timer(void)
{
    /* Stop the timer from producing further interrupts and remove all existing timeouts. */
    free(min_heap);
    clock.regs->mux = 0;
    configure_timeout(clock.regs, MESON_TIMER_A, false, false, TIMEOUT_TIMEBASE_1_MS, 0);
    clock.regs->timer_e = 0;
    clock.regs->timer_e_hi = 0;
    free((void *)clock.regs);

    return CLOCK_R_OK;
}

static int remove_from_heap(int index, uint32_t id) {
    push(id);
    if (index == 0) {
        SGLIB_HEAP_DELETE(timer_node, min_heap, first_free, max_timers, MINHEAP_TIME_COMPARATOR);
    } else {
        SGLIB_HEAP_REMOVE(timer_node, min_heap, index, first_free, MINHEAP_TIME_COMPARATOR);
    }
    
    if (first_free < max_timers / 2) {
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
    if (!SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, first_free)) {
        uint64_t new = SGLIB_HEAP_GET_MIN(min_heap).time_expired - read_timestamp(clock.regs) / 1000;
        write_timeout(clock.regs, MESON_TIMER_A, new);
    }
}

static int invoke_callbacks()
{
    timer_node first_elem;
    do {
        first_elem = SGLIB_HEAP_GET_MIN(min_heap);
        first_elem.callback(first_elem.id, first_elem.data);
        if (remove_from_heap(0, first_elem.id)) {
            return 1;
        }
    } while (first_elem.time_expired == SGLIB_HEAP_GET_MIN(min_heap).time_expired);
    return 0;
}