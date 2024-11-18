#include <stdio.h>
#include <stdlib.h>
#include <utils/util.h>
#include <clock/clock.h>
#include <clock/watchdog.h>
#include <clock/timestamp.h>
#include <clock/device.h>
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
    seL4_Signal((0x4));
}

static inline void handle_operation(int fd)
{
    seL4_Word op = seL4_GetMR(0);
    switch(op) {
        case REGISTER_TIMER:
            sos_write(fd, "here\n", strlen("here\n"));
            uint64_t delay = seL4_GetMR(1);
            register_timer(delay, wakeup, NULL);
            sos_write(fd, "never got out", strlen("never got out"));
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
    int fd = sos_open("console", 1);
    while (1) {
        seL4_Word sender;
        seL4_MessageInfo_t message;
        if (have_reply) {
            message = seL4_ReplyRecv(TIMER_IPC_EP_CAP, reply_msg, &sender, TIMER_REPLY);
        } else {
            message = seL4_Recv(TIMER_IPC_EP_CAP, &sender, TIMER_REPLY);
        }
        if (sender & IRQ_EP_BADGE) {
            sos_write(fd, "irqworks", strlen("irqworks"));
            timer_irq(NULL, 0, 0);
            have_reply = false;
        } else {
            handle_operation(fd);
            have_reply = true;
        }
    }
}


int main(void)
{
    // start timer here from pcb
    start_timer(0xb0001000);
    driver_loop();
}
