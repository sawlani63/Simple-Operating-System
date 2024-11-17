#include <stdio.h>
#include <stdlib.h>
#include <utils/util.h>
#include <clock/clock.h>
#include <string.h>

#include <sos.h>

#define IRQ_EP_BADGE         BIT(seL4_BadgeBits - 1ul)

#define TIMER_IPC_EP_CAP (0x2)
#define TIMER_REPLY (0x3)

#define REGISTER_TIMER 0
#define MICRO_TIMESTAMP 1
#define MILLI_TIMESTAMP 2

static inline void wakeup(UNUSED uint32_t id, void *data)
{
    seL4_CPtr sleep_signal = (seL4_CPtr) data;
    seL4_Signal(sleep_signal);
}

static inline void handle_operation()
{
    seL4_Word op = seL4_GetMR(0);
    switch(op) {
        case REGISTER_TIMER:
            //sos_write(fd, "going to reg timer", strlen("going to reg timer"));
            register_timer(seL4_GetMR(1), wakeup, seL4_GetMR(2));
            //sos_write(fd, "done to reg timer", strlen("done to reg timer"));
            break;
        case MICRO_TIMESTAMP:
            seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
            break;
        case MILLI_TIMESTAMP:
            seL4_SetMR(0, timestamp_ms(timestamp_get_freq()));
            break;
        default:
            //sos_write(fd, "wtf bruh", strlen("wtf bruh"));
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
        //seL4_Wait((0x4), &sender);
        //sos_write(fd, "received\n", strlen("received\n"));
        if (sender & IRQ_EP_BADGE) {
            //sos_write(fd, "irqworks\n", strlen("irqworks\n"));
            timer_irq(NULL, 0, 0);
            //sos_write(fd, "not stuck in timer irq", strlen("not stuck in timer irq"));
            have_reply = false;
        } else {
            //sos_write(fd, "op\n", strlen("op\n"));
            handle_operation();
            have_reply = true;
            //sos_write(fd, "backfromop\n", strlen("backfromop\n"));
        }
    }
}


int main(void)
{
    // start timer here from pcb
    //int fd = sos_open("console", 1);
    //sos_write(fd, "clock start\n", strlen("clock start\n"));
    driver_loop();
}
