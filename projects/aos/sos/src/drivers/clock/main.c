#include <stdio.h>
#include <stdlib.h>
#include <utils/util.h>
#include "../../utils.h"
#include <clock/clock.h>

#include <sos.h>

#define TIMER_IPC_EP_CAP (0x2)

#define REGISTER_TIMER 0
#define MICRO_TIMESTAMP 1
#define MILLI_TIMESTAMP 2

static inline void wakeup(UNUSED uint32_t id, void *data)
{
    seL4_CPtr sleep_signal = (seL4_CPtr) data;
    seL4_Signal(sleep_signal);
}

static inline handle_operation(seL4_Word op)
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

static void driver_loop(int fd)
{
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    //sos_write(fd, "reply", strlen("reply"));

    while (1) {
        seL4_Word sender;
        seL4_MessageInfo_t message = seL4_ReplyRecv(TIMER_IPC_EP_CAP, reply_msg, &sender, (0x3));

        /*if (sender & IRQ_EP_BADGE) {
            handle_irq();
        } else {
            handle_operation(seL4_GetMR(0));
        }*/
        //sos_write(fd, "going to op", strlen("going to op"));
        handle_operation(seL4_GetMR(0));
        //sos_write(fd, "out of op", strlen("out of op"));
    }
}


int main(void)
{
    // start timer here from pcb
    //sos_write(1, "proc started", strlen("proc started"));
    driver_loop(1);
}
