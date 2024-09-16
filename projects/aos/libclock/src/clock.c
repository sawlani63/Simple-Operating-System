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

/* The functions in src/device.h should help you interact with the timer
 * to set registers and configure timeouts. */
#include "device.h"

#include <clock/timestamp.h>

#define MAX_TIMERS 32
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

timer_node *min_heap;
int next_free = 0;
uint32_t curr_id = 0;

void reset_timer_a();
void invoke_callback();

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
    configure_timestamp(clock.regs, TIMEOUT_TIMEBASE_1_MS);

    /* Allocate the min heap for keeping track of timers. */
    min_heap = malloc(sizeof(timer_node) * MAX_TIMERS);
    if (min_heap == NULL) {
        return CLOCK_R_UINT;
    }

    return CLOCK_R_OK;
}

timestamp_t get_time(void)
{
    return read_timestamp(clock.regs);
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{
    if (SGLIB_HEAP_IS_FULL(timer_node, min_heap, next_free, MAX_TIMERS)) {
        return 0;
    } else if (SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, next_free)) {
        /* NOTE: Timer A is 16 bit whereas delay is 64 bit. May need to be changed later.*/
        write_timeout(clock.regs, MESON_TIMER_A, delay);
    }
    /* Combine the e_hi and e_lo registers then add the delay and put it in minheap.*/
    uint64_t expiry_time = (uint64_t) clock.regs->timer_e_hi << 32 || clock.regs->timer_e;
    /* NOTE: IDs are currently just incremented per register. Likely needs to change later.*/
    timer_node node = {++curr_id, expiry_time, callback, data};
    SGLIB_HEAP_ADD(timer_node, min_heap, node, next_free, MAX_TIMERS, MINHEAP_TIME_COMPARATOR);
    return curr_id;
}

int remove_timer(uint32_t id)
{
    if (SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, next_free)) {
        return -1;
    }

    int index;
    timer_node node = {id, 0, NULL, NULL};
    SGLIB_HEAP_FIND(timer_node, min_heap, next_free, MINHEAP_ID_COMPARATOR, node, index);
    if (index == -1) {
        return CLOCK_R_FAIL;
    }
    SGLIB_HEAP_REMOVE(timer_node, min_heap, index, next_free, MINHEAP_TIME_COMPARATOR, node);
    if (index == 0) {
        reset_timer_a();
    }
    return CLOCK_R_OK;
}

int timer_irq(
    void *data,
    seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    /* Invoke the callback to wake up the relevant thread */
    invoke_callback();
    /* Remove the invoked callback from the heap and rebalance */
    SGLIB_HEAP_DELETE(timer_node, min_heap, next_free, MAX_TIMERS, MINHEAP_TIME_COMPARATOR);
    /* Reset timer a */
    reset_timer_a();
    /* Acknowledge that the IRQ has been handled */
    seL4_IRQHandler_Ack(irq_handler);
    return CLOCK_R_OK;
}

int stop_timer(void)
{
    /* Stop the timer from producing further interrupts and remove all
     * existing timeouts */
    free(min_heap);
    clock.regs->mux = 0;
    clock.regs->timer_a = 0;
    clock.regs->timer_e = 0;
    clock.regs->timer_e_hi = 0;
    free((void *)clock.regs);

    return CLOCK_R_OK;
}

void reset_timer_a()
{
    if (!SGLIB_HEAP_IS_EMPTY(timer_node, min_heap, next_free))
    {
        uint64_t new_delay = SGLIB_HEAP_FIRST_ELEMENT(min_heap).time_expired - read_timestamp(clock.regs);
        write_timeout(clock.regs, MESON_TIMER_A, new_delay);
    } // else write to 0?
}

void invoke_callback()
{
    timer_node first_elem = SGLIB_HEAP_FIRST_ELEMENT(min_heap);
    first_elem.callback(first_elem.id, first_elem.data);
}