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

#define TIMER_VADDR (0xb0001000)
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
        //default:
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
        if (sender == (meson_timeout_irq(MESON_TIMER_A))) {
            sos_write(fd, "irqworks b", strlen("irqworks b"));
            timer_irq(NULL, meson_timeout_irq(MESON_TIMER_A), (0x5));
            have_reply = false;
        } else if (sender == (meson_timeout_irq(MESON_TIMER_B))) {
            sos_write(fd, "irqworks A", strlen("irqworks A"));
            timer_irq(NULL, meson_timeout_irq(MESON_TIMER_B), (0x6));
            have_reply = false;
        } else {
            handle_operation(fd);
            have_reply = true;
        }
    }
}


int main(void)
{
    int res = start_timer(TIMER_VADDR);
    if (res < 0) {
        return 1;
    }
    driver_loop();
    return 0;
}
