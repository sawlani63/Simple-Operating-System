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

#include <stdio.h>

static struct {
    volatile meson_timer_reg_t *regs;
    /* Add fields as you see necessary */
} clock;

int start_timer(unsigned char *timer_vaddr)
{
    meson_timer_reg_t temp;
    clock.regs = &temp;
    
    uint32_t *register_addresses = (uint32_t *) (timer_vaddr + TIMER_REG_START);
    clock.regs->mux = register_addresses[0];
    clock.regs->timer_a = register_addresses[1];
    clock.regs->timer_b = register_addresses[2];
    clock.regs->timer_c = register_addresses[3];
    clock.regs->timer_d = register_addresses[4];
    printf("mux: %p, a: %p, b: %p, c: %p, d: %p\n", clock.regs->mux, register_addresses[1], register_addresses[2], register_addresses[3], register_addresses[4]);

    return CLOCK_R_OK;
}

uint32_t register_timer(uint64_t delay, timer_callback_t callback, void *data)
{
    return 0;
}

int remove_timer(uint32_t id)
{
    return CLOCK_R_FAIL;
}

int timer_irq(
    void *data,
    seL4_Word irq,
    seL4_IRQHandler irq_handler
)
{
    /* Handle the IRQ */

    /* Acknowledge that the IRQ has been handled */
    return CLOCK_R_FAIL;
}

int stop_timer(void)
{
    /* Stop the timer from producing further interrupts and remove all
     * existing timeouts */
    return CLOCK_R_FAIL;
}
