#include "boot_driver.h"

#include <clock/clock.h>
#include <aos/debug.h>

#include "elfload.h"
#include "utils.h"
#include "frame_table.h"
#include "console.h"
#include "vmem_layout.h"
#include "mapping.h"

int init_driver_irq_handling(seL4_IRQControl irq_control, seL4_Word irq, int level, user_process_t user_process, seL4_CPtr ntfn)
{
    seL4_CPtr handler_cptr = cspace_alloc_slot(&cspace);
    if (handler_cptr == seL4_CapNull) {
        ZF_LOGE("Could not allocate slot for timer irq");
        return -1;
    }
    seL4_CPtr notification_cptr = cspace_alloc_slot(&cspace);
    if (notification_cptr == seL4_CapNull) {
        ZF_LOGE("Could not allocate slot for timer irq");
        return -1;
    }
    seL4_Error err = cspace_irq_control_get(&cspace, handler_cptr, irq_control, irq, level);
    if (err != seL4_NoError) {
        ZF_LOGE("Could not allocate irq handler for timer irq");
        return -1;
    }
    err = cspace_mint(&cspace, notification_cptr, &cspace, ntfn, seL4_CanWrite, irq);
    if (err != seL4_NoError) {
        ZF_LOGE("Could not mint notification for timer irq");
        return -1;
    }
    err = seL4_IRQHandler_SetNotification(handler_cptr, notification_cptr);
    if (err != seL4_NoError) {
        ZF_LOGE("Could not set notification for timer irq %d", err);
        return -1;
    }
    seL4_CPtr handler_slot = cspace_alloc_slot(&user_process.cspace);
    err = cspace_mint(&user_process.cspace, handler_slot, &cspace, handler_cptr, seL4_AllRights, 0);
    if (err) {
        ZF_LOGE("Failed to mint IRQ handler");
    }
    seL4_IRQHandler_Ack((seL4_IRQHandler) handler_cptr);
    return 0;
}