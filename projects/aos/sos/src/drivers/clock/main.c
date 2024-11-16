#include <stdio.h>
#include <stdlib.h>
#include <utils/util.h>
#include <clock/clock.h>
#include "sos_syscall.h"

#define IRQ_EP_BADGE         BIT(seL4_BadgeBits - 1ul)

#define TIMER_IPC_EP_CAP (0x2)
#define TIMER_REPLY (0x3)
#define TIMER_IRQ_HANDLER (0x4)
#define TIMER_NOTIFICATION (0x5)

#define REGISTER_TIMER 0
#define MICRO_TIMESTAMP 1
#define MILLI_TIMESTAMP 2

static inline void wakeup(UNUSED uint32_t id, void *data)
{
    seL4_CPtr sleep_signal = (seL4_CPtr) data;
    seL4_Signal(sleep_signal);
}

static inline void handle_operation(seL4_Word op)
{
    switch(op) {
        case REGISTER_TIMER:
            register_timer(seL4_GetMR(1), wakeup, seL4_GetMR(2));
            break;
        case MICRO_TIMESTAMP:
            seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
            break;
        case MILLI_TIMESTAMP:
            seL4_SetMR(0, timestamp_ms(timestamp_get_freq()));
            break;
        default:
            /* Do nothing */
    }
}

static void driver_loop()
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    bool have_reply = false;

    while (1) {
        seL4_Word sender;
        seL4_MessageInfo_t message;
        if (have_reply) {
            message = seL4_ReplyRecv(TIMER_IPC_EP_CAP, reply_msg, &sender, TIMER_REPLY);
        } else {
            message = seL4_Recv(TIMER_IPC_EP_CAP, &sender, TIMER_REPLY);
        }
        printf("PLS PRINT");
        if (sender & IRQ_EP_BADGE) {
            timer_irq(NULL, 0, TIMER_IRQ_HANDLER);
            have_reply = false;
        } else {
            handle_operation(seL4_GetMR(0));
            have_reply = true;
        }
    }
}


int main(void)
{
    // start timer here from pcb
    driver_loop();
    printf("IN HERE");
}
