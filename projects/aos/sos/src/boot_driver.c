#include "boot_driver.h"

#include <clock/clock.h>
#include <aos/debug.h>

#include "elfload.h"
#include "utils.h"
#include "frame_table.h"
#include "console.h"
#include "vmem_layout.h"
#include "mapping.h"

#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

extern seL4_CPtr sched_ctrl_start;
extern seL4_CPtr sched_ctrl_end;
extern seL4_CPtr nfs_signal;

clock_process_t clock_driver;
extern seL4_CPtr ipc_ep;

NORETURN void syscall_loop(void *arg);

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

static uintptr_t init_clock_process_stack(cspace_t *cspace, seL4_CPtr local_vspace, seL4_CPtr clock_vspace)
{
    addrspace_t *as = clock_driver.addrspace;
    /* Allocating a region for the stack */
    as->stack_reg = as_define_stack(as);
    if (as->stack_reg == NULL) {
        ZF_LOGD("Failed to alloc stack region");
        return -1;
    }

    /* virtual addresses in the target process' address space */
    uintptr_t stack_top = PROCESS_STACK_TOP;
    uintptr_t stack_bottom = PROCESS_STACK_TOP - PAGE_SIZE_4K;
    /* virtual addresses in the SOS's address space */
    void *local_stack_top  = (seL4_Word *) SOS_SCRATCH;
    uintptr_t local_stack_bottom = SOS_SCRATCH - PAGE_SIZE_4K;

    /* Create a stack frame */
    clock_driver.stack_frame = clock_alloc_frame(stack_bottom, clock_driver.pid, 0);
    if (clock_driver.stack_frame == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return -1;
    }
    clock_driver.stack = frame_page(clock_driver.stack_frame);

    /* Map in the stack frame for the user app */
    seL4_Error err = sos_map_frame(cspace, clock_vspace, stack_bottom, REGION_RD | REGION_WR,
                                   clock_driver.stack_frame, as);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return -1;
    }

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return -1;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, clock_driver.stack, seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(cspace, local_stack_cptr);
        ZF_LOGE("Failed to copy cap");
        return -1;
    }

    /* map it into the sos address space */
    err = map_frame(cspace, local_stack_cptr, local_vspace, local_stack_bottom, seL4_AllRights,
                    seL4_ARM_Default_VMAttributes);
    if (err != seL4_NoError) {
        cspace_delete(cspace, local_stack_cptr);
        cspace_free_slot(cspace, local_stack_cptr);
        return -1;
    }

    int index = -2;

    /* null terminate the aux vectors */
    index = stack_write(local_stack_top, index, 0);
    index = stack_write(local_stack_top, index, 0);

    /* write the aux vectors */
    index = stack_write(local_stack_top, index, PAGE_SIZE_4K);
    index = stack_write(local_stack_top, index, AT_PAGESZ);

    index = stack_write(local_stack_top, index, PROCESS_IPC_BUFFER);
    index = stack_write(local_stack_top, index, AT_SEL4_IPC_BUFFER_PTR);

    /* null terminate the environment pointers */
    index = stack_write(local_stack_top, index, 0);

    /* we don't have any env pointers - skip */

    /* null terminate the argument pointers */
    index = stack_write(local_stack_top, index, 0);

    /* no argpointers - skip */

    /* set argc to 0 */
    stack_write(local_stack_top, index, 0);

    /* adjust the initial stack top */
    stack_top += (index * sizeof(seL4_Word));

    /* the stack *must* remain aligned to a double word boundary,
     * as GCC assumes this, and horrible bugs occur if this is wrong */
    assert(index % 2 == 0);
    assert(stack_top % (sizeof(seL4_Word) * 2) == 0);

    /* unmap our copy of the stack */
    err = seL4_ARM_Page_Unmap(local_stack_cptr);
    assert(err == seL4_NoError);

    /* delete the copy of the stack frame cap */
    err = cspace_delete(cspace, local_stack_cptr);
    assert(err == seL4_NoError);

    /* mark the slot as free */
    cspace_free_slot(cspace, local_stack_cptr);

    /* Exend the stack with extra pages */
    for (int page = 0; page < INITIAL_PROCESS_EXTRA_STACK_PAGES; page++) {
        stack_bottom -= PAGE_SIZE_4K;
        frame_ref_t frame = clock_alloc_frame(stack_bottom, clock_driver.pid, 0);
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return -1;
        }

        err = sos_map_frame(cspace, clock_vspace, stack_bottom,
                            REGION_RD | REGION_WR, frame, as);
        if (err != 0) {
            ZF_LOGE("Unable to map stack for user app");
            return -1;
        }
    }

    return stack_top;
}

int start_clock_process()
{
    clock_driver = (clock_process_t) {0};
    clock_driver.pid = TIMER_ID;

    clock_driver.reply_ut = alloc_retype(&clock_driver.reply, seL4_ReplyObject, seL4_ReplyBits);
    if (clock_driver.reply_ut == NULL){
        ZF_LOGE("Failed to create reply object");
        return -1;
    }

    clock_driver.ntfn_ut = alloc_retype(&clock_driver.ntfn, seL4_NotificationObject, seL4_NotificationBits);
    if (clock_driver.ntfn_ut == NULL) {
        ZF_LOGE("Failed to create notification");
        return -1;
    }

    /* Create a VSpace */
    clock_driver.vspace_ut = alloc_retype(&clock_driver.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (clock_driver.vspace_ut == NULL) {
        ZF_LOGE("Failed to create vspace");
        return -1;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, clock_driver.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        return -1;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &clock_driver.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        return -1;
    }

    /* Initialise the process address space */
    clock_driver.addrspace = as_create();
    if (clock_driver.addrspace == NULL) {
        ZF_LOGE("Failed to create address space");
        return -1;
    }

    mem_region_t *region = as_define_ipc_buff(clock_driver.addrspace);
    if (region == NULL) {
        ZF_LOGE("Failed to create ipc buffer region");
        return -1;
    }

    /* Create an IPC buffer */
    clock_driver.ipc_buffer_frame = clock_alloc_frame(PROCESS_IPC_BUFFER, clock_driver.pid, 1);
    if (clock_driver.ipc_buffer_frame == NULL_FRAME) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        return -1;
    }
    clock_driver.ipc_buffer = frame_page(clock_driver.ipc_buffer_frame);

    seL4_CPtr slot1 = cspace_alloc_slot(&clock_driver.cspace);
    if (slot1 == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot");
        return -1;
    }
    seL4_CPtr slot2 = cspace_alloc_slot(&clock_driver.cspace);
    if (slot2 == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot");
        return -1;
    }
    seL4_CPtr slot3 = cspace_alloc_slot(&clock_driver.cspace);
    if (slot3 == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot");
        return -1;
    }
    seL4_CPtr slot4 = cspace_alloc_slot(&clock_driver.cspace);
    if (slot4 == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot");
        return -1;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&clock_driver.cspace, slot1, &cspace, ipc_ep, seL4_AllRights, (seL4_Word) clock_driver.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return -1;
    }
    err = cspace_mint(&clock_driver.cspace, slot2, &cspace, ipc_ep, seL4_AllRights, (seL4_Word) clock_driver.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return -1;
    }
    err = cspace_mint(&clock_driver.cspace, slot3, &cspace, clock_driver.reply, seL4_AllRights, (seL4_Word) clock_driver.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return -1;
    }
    err = cspace_mint(&clock_driver.cspace, slot4, &cspace, clock_driver.ntfn, seL4_AllRights, (seL4_Word) clock_driver.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return -1;
    }

    /* Create a new TCB object */
    clock_driver.tcb_ut = alloc_retype(&clock_driver.tcb, seL4_TCBObject, seL4_TCBBits);
    if (clock_driver.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        return -1;
    }
    
    /* Configure the TCB */
    err = seL4_TCB_Configure(clock_driver.tcb,
                             clock_driver.cspace.root_cnode, seL4_NilData,
                             clock_driver.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             clock_driver.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        return -1;
    }
    
    /* Create scheduling context */
    clock_driver.sched_context_ut = alloc_retype(&clock_driver.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (clock_driver.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        return -1;
    }
    
    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, clock_driver.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        return -1;
    }
    
    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(clock_driver.tcb, seL4_CapInitThreadTCB, seL4_MinPrio, 0,
                                  clock_driver.sched_context, clock_driver.ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        return -1;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(clock_driver.tcb, TIMER_DEVICE);

    /* Read the ELF header from NFS */
    ZF_LOGI("\nStarting \"%s\"...\n", TIMER_DEVICE);
    unsigned long elf_size;
    elf_t elf_file = {};
    open_file *elf = file_create(TIMER_DEVICE, O_RDWR, nfs_pwrite_file, nfs_pread_file);
    char *elf_base = elf_load_header(elf, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to open or read %s from NFS", TIMER_DEVICE);
        return -1;
    }

    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        return -1;
    }

    /* set up the stack */
    seL4_Word sp = init_clock_process_stack(&cspace, seL4_CapInitThreadVSpace, clock_driver.vspace);
    if ((int) sp == -1) {
        ZF_LOGE("Failed to set up the stack");
        return -1;
    }

    /* Allocating a region for the heap */
    clock_driver.addrspace->heap_reg = as_define_heap(clock_driver.addrspace);
    if (clock_driver.addrspace->heap_reg == NULL) {
        ZF_LOGE("Failed to create the heap region");
        return -1;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, clock_driver.vspace, PROCESS_IPC_BUFFER, REGION_RD | REGION_WR,
                        clock_driver.ipc_buffer_frame, clock_driver.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        return -1;
    }

    /* load the elf image from nfs */
    unsigned size = 0;
    err = elf_load(&cspace, &elf_file, elf, clock_driver.addrspace, clock_driver.vspace, &size, clock_driver.pid);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return -1;
    }

    /* close the elf file on nfs */
    io_args args = {.signal_cap = nfs_signal};
    int nfs_err = nfs_close_file(elf, nfs_async_close_cb, &args);
    if (nfs_err < 0) {
        ZF_LOGE("NFS: Error in closing ELF file");
        return -1;
    }
    file_destroy(elf);

    /* Start the new process */
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };
    err = seL4_TCB_WriteRegisters(clock_driver.tcb, 1, 0, 2, &context);
    if (err) {
        ZF_LOGE("Failed to write registers");
        return -1;
    }

    free(elf_base);
    err = seL4_TCB_BindNotification(clock_driver.tcb, clock_driver.ntfn);
    if (err) {
        ZF_LOGE("Failed to bind notification");
        return -1;
    }
    return 0;
}

int init_driver_irq_handling(seL4_IRQControl irq_control, seL4_Word irq, int level)
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
    err = cspace_mint(&cspace, notification_cptr, &cspace, clock_driver.ntfn, seL4_CanWrite, irq);
    if (err != seL4_NoError) {
        ZF_LOGE("Could not mint notification for timer irq");
        return -1;
    }
    err = seL4_IRQHandler_SetNotification(handler_cptr, notification_cptr);
    if (err != seL4_NoError) {
        ZF_LOGE("Could not set notification for timer irq %d", err);
        return -1;
    }
    seL4_CPtr handler_slot = cspace_alloc_slot(&clock_driver.cspace);
    err = cspace_mint(&clock_driver.cspace, handler_slot, &cspace, handler_cptr, seL4_AllRights, 0);
    if (err) {
        ZF_LOGE("Failed to mint IRQ handler");
    }
    seL4_IRQHandler_Ack((seL4_IRQHandler) handler_cptr);
    return 0;
}