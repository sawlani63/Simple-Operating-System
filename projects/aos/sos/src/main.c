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
#include <autoconf.h>
#include <utils/util.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <cspace/cspace.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>

#include <clock/clock.h>
#include <cpio/cpio.h>
#include <elf/elf.h>
#include <networkconsole/networkconsole.h>

#include <sel4runtime.h>
#include <sel4runtime/auxv.h>

#include "bootstrap.h"
#include "irq.h"
#include "network.h"
#include "frame_table.h"
#include "drivers/uart.h"
#include "ut.h"
#include "vmem_layout.h"
#include "mapping.h"
#include "elfload.h"
#include "syscalls.h"
#include "tests.h"
#include "utils.h"
#include "threads.h"
#include <sos/gen_config.h>
#ifdef CONFIG_SOS_GDB_ENABLED
#include "debugger.h"
#endif /* CONFIG_SOS_GDB_ENABLED */

#include <aos/vsyscall.h>
#include "fs.h"
#include "thread_pool.h"
#include "addrspace.h"

/*
 * To differentiate between signals from notification objects and and IPC messages,
 * we assign a badge to the notification object. The badge that we receive will
 * be the bitwise 'OR' of the notification object badge and the badges
 * of all pending IPC messages.
 *
 * All badged IRQs set high bit, then we use unique bits to
 * distinguish interrupt sources.
 */
#define IRQ_EP_BADGE         BIT(seL4_BadgeBits - 1ul)
#define IRQ_IDENT_BADGE_BITS MASK(seL4_BadgeBits - 1ul)

#define APP_NAME             "console_test"
#define APP_PRIORITY         (0)
#define APP_EP_BADGE         (101)

#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

#define SYSCALL_SOS_OPEN SYS_openat
#define SYSCALL_SOS_CLOSE SYS_close
#define SYSCALL_SOS_READ SYS_readv
#define SYSCALL_SOS_WRITE SYS_writev
#define SYSCALL_SOS_USLEEP SYS_nanosleep
#define SYSCALL_SOS_TIME_STAMP SYS_clock_gettime
#define SYSCALL_SYS_BRK SYS_brk

/* The linker will link this symbol to the start address  *
 * of an archive of attached applications.                */
extern char _cpio_archive[];
extern char _cpio_archive_end[];
extern char __eh_frame_start[];
/* provided by gcc */
extern void (__register_frame)(void *);

/* root tasks cspace */
cspace_t cspace;

static seL4_CPtr sched_ctrl_start;
static seL4_CPtr sched_ctrl_end;

/* the one process we start */
static struct {
    ut_t *tcb_ut;
    seL4_CPtr tcb;
    ut_t *vspace_ut;
    seL4_CPtr vspace;

    ut_t *ipc_buffer_ut;
    seL4_CPtr ipc_buffer;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    frame_ref_t stack_frame;
    seL4_CPtr stack;

    addrspace_t *addrspace;

    char *cache_curr_path;
    int curr_len;
    int open_len;
    int cache_curr_mode;
} user_process;

struct network_console *console;

bool console_open_for_read = false;

seL4_CPtr sem_cptr;
sync_bin_sem_t *syscall_sem = NULL;

static void syscall_sos_open(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_close(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_read(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_write(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_usleep(bool *have_reply, struct task *curr_task);
static void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg);
static void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number);
static void wakeup(UNUSED uint32_t id, void *data);

void handle_vm_fault(seL4_CPtr reply) {
    addrspace_t *as = user_process.addrspace;
    
    /* A VM Fault is an IPC. Check the seL4 Manual section 6.2.7 for message structure. We also
     * page align the vaddr since the Hardware Page Table expects addresses to be page aligned. */
    seL4_Word fault_addr = seL4_GetMR(seL4_VMFault_Addr) & ~(PAGE_SIZE_4K - 1);

    if (as == NULL || as->page_table == NULL) {
        /* We encountered some weird error where the address space for the user
         * process or its page table was uninitialised. */
        return;
    }

    /* We use our shadow page table which follows the same structure as the hardware one.
     * Check the seL4 Manual section 7.1.1 for hardware virtual memory objects. Importantly
     * the top-most 16 bits of the virtual address are unused bits, so we ignore them. */
    uint16_t l1_index = (fault_addr >> 39) & 0x1FF; /* Top 9 bits */
    uint16_t l2_index = (fault_addr >> 30) & 0x1FF; /* Next 9 bits */
    uint16_t l3_index = (fault_addr >> 21) & 0x1FF; /* Next 9 bits */
    uint16_t l4_index = (fault_addr >> 12) & 0x1FF; /* Next 9 bits */

    /* Cache the related page table entries so we don't have to perform lots of dereferencing. */
    pt_entry ****l1_pt = as->page_table;
    pt_entry ***l2_pt = NULL;
    pt_entry **l3_pt = NULL;
    pt_entry *l4_pt = NULL;
    if (l1_pt[l1_index] != NULL) {
        l2_pt = l1_pt[l1_index];
        if (l2_pt[l2_index] != NULL) {
            l3_pt = l2_pt[l2_index];
            if (l3_pt[l3_index] != NULL) {
                l4_pt = l3_pt[l3_index];
            }
        }
    }

    /* If there already exists a valid entry in our page table, reload the Hardware Page Table and
     * unblock the caller with an empty message. */
    if (l4_pt != NULL && l4_pt[l4_index].frame != NULL_FRAME) {
        pt_entry entry = l4_pt[l4_index];
        if (!debug_is_read_fault() && (entry.perms & REGION_WR) == 0) {
            return;
        }
        if (sos_map_frame_impl(&cspace, frame_page(entry.frame), user_process.vspace, fault_addr,
                               seL4_CapRights_new(0, 0, entry.perms & REGION_RD, (entry.perms >> 1) & 1),
                               l4_pt + l4_index) != 0) {
            return;
        }
        seL4_NBSend(reply, seL4_MessageInfo_new(0, 0, 0, 0));
    }

    /* Check if the fault occurred in a valid region. */
    mem_region_t *reg;
    for (reg = as->regions; reg != NULL; reg = reg->next) {
        seL4_Word top_of_region = reg->base + reg->size;
        if (fault_addr >= reg->base && fault_addr < top_of_region) {
            /* We need this permissions check for demand paging that will later occur on the Hardware
             * Page Table. In the case a page in the HPT gets swapped to disk yet remains on the
             * Shadow Page Table, we need some way to know if the user is allowed to write to it. */
            if (!debug_is_read_fault() && (reg->perms & REGION_WR) == 0) {
                return;
            }
            /* Fault occurred in a valid region and permissions line up so we can safely break out. */
            break;
        } else if (top_of_region == PROCESS_STACK_TOP && fault_addr < top_of_region && fault_addr >= as->heap_top) {
            /* Expand the stack. */
            reg->base = fault_addr;
            reg->size = PROCESS_STACK_TOP - fault_addr;
            break;
        }
    }

    if (reg == NULL) {
        /* We did not find a valid region for this memory.*/
        return;
    }

    /* Allocate any necessary levels within the shadow page table. */
    if (l2_pt == NULL) {
        l2_pt = l1_pt[l1_index] = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry *));
        if (l2_pt == NULL) {
            /* Failed to allocate memory for shadow page table, just block the caller. */
            return;
        }
    }
    if (l3_pt == NULL) {
        l3_pt = l2_pt[l2_index] = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry *));
        if (l3_pt == NULL) {
            /* Failed to allocate memory for shadow page table, just block the caller. */
            return;
        }
    }
    if (l4_pt == NULL) {
        l4_pt = l3_pt[l3_index] = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
        if (l4_pt == NULL) {
            /* Failed to allocate memory for shadow page table, just block the caller. */
            return;
        }
    }

    /* Create slot for the frame to load the data into. */
    seL4_CPtr loadee_frame = cspace_alloc_slot(&cspace);
    if (loadee_frame == seL4_CapNull) {
        ZF_LOGD("Failed to alloc slot");
        return;
    }

    /* Allocate a new frame to be mapped by the shadow page table. */
    frame_ref_t frame_ref = l4_pt[l4_index].frame = alloc_frame();
    if (frame_ref == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return;
    }
    l4_pt[l4_index].perms = reg->perms;

    /* Assign the appropriate rights for the frame we are about to map. */
    seL4_CapRights_t rights = seL4_CapRights_new(0, 0, reg->perms & REGION_RD, (reg->perms >> 1) & 1);

    /* Copy the frame capability into the slot we just assigned within the root cspace. */
    seL4_Error err = cspace_copy(&cspace, loadee_frame, &cspace, frame_page(frame_ref), rights);
    if (err != seL4_NoError) {
        ZF_LOGD("Failed to untyped reypte");
        return;
    }

    /* Map the frame into the relevant page tables. */
    if (sos_map_frame_impl(&cspace, loadee_frame, user_process.vspace,
                           fault_addr, rights, l4_pt + l4_index) != 0) {
        return;
    }

    /* Respond with an empty message just to unblock the caller. */
    seL4_NBSend(reply, seL4_MessageInfo_new(0, 0, 0, 0));
}

/**
 * Deals with a syscall and sets the message registers before returning the
 * message info to be passed through to seL4_ReplyRecv()
 */
void handle_syscall(void *arg)
{
    struct task *curr_task = (struct task *) arg;
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = curr_task->msg[0];

    /* Set the reply flag */
    bool have_reply = true;

    /* Process system call */
    switch (syscall_number) {
        case SYSCALL_SOS_OPEN:
            syscall_sos_open(&reply_msg, curr_task);
            break;
        case SYSCALL_SOS_CLOSE:
            syscall_sos_close(&reply_msg, curr_task);
            break;
        case SYSCALL_SOS_READ:
            syscall_sos_read(&reply_msg, curr_task);
            break;
        case SYSCALL_SOS_WRITE:
            syscall_sos_write(&reply_msg, curr_task);
            break;
        case SYSCALL_SOS_USLEEP:
            syscall_sos_usleep(&have_reply, curr_task);
            break;
        case SYSCALL_SOS_TIME_STAMP:
            syscall_sos_time_stamp(&reply_msg);
            break;
        case SYSCALL_SYS_BRK:
            syscall_sys_brk(&reply_msg, curr_task);
            break;
        default:
            syscall_unknown_syscall(&reply_msg, syscall_number);
    }

    if (have_reply) {
        seL4_NBSend(curr_task->reply, reply_msg);
        free_untype(&curr_task->reply, curr_task->reply_ut);
    }
}

NORETURN void syscall_loop(seL4_CPtr ep)
{
    seL4_CPtr reply;

    /* Create reply object */
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }

    while (1) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t message = seL4_Recv(ep, &badge, reply);

        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification object! */
            sos_handle_irq_notification(&badge, false);
        } else if (label == seL4_Fault_NullFault) {         
            /* Create a new task for one of our worker threads in the thread pool */   
            struct task task = {.reply_ut = reply_ut, .reply = reply};
            seL4_Word msg[NUM_MSG_REGISTERS]
                = {seL4_GetMR(0), seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3), seL4_GetMR(4)};
            memcpy(task.msg, msg, sizeof(seL4_Word) * 5);
            submit_task(task);
            
            /* To stop the main thread from overwriting the worker thread's
             * reply object, we give the main thread a new one */
            reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
            if (reply_ut == NULL) {
                ZF_LOGF("Failed to alloc reply object ut");
            }
        } else if (label == seL4_Fault_VMFault) {
            handle_vm_fault(reply);
        } else {
            /* some kind of fault */
            debug_print_fault(message, APP_NAME);
            /* dump registers too */
            debug_dump_registers(user_process.tcb);

            ZF_LOGF("The SOS skeleton does not know how to handle faults!");
        }
    }
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
static uintptr_t init_process_stack(cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file)
{
    /* Create a stack frame */
    user_process.stack_frame = alloc_frame();
    if (user_process.stack_frame == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return -1;
    }

    /* copy it */
    seL4_Error err = cspace_copy(cspace, user_process.stack, frame_table_cspace(),
                                 frame_page(user_process.stack_frame), seL4_AllRights);
    if (err != seL4_NoError) {
        ZF_LOGD("Failed to untyped reypte");
        return -1;
    }

    /* virtual addresses in the target process' address space */
    uintptr_t stack_top;
    uintptr_t stack_bottom = PROCESS_STACK_TOP - as_define_stack(user_process.addrspace, &stack_top);
    /* virtual addresses in the SOS's address space */
    void *local_stack_top  = (seL4_Word *) SOS_SCRATCH;
    uintptr_t local_stack_bottom = SOS_SCRATCH - PAGE_SIZE_4K;

    /* find the vsyscall table */
    uintptr_t *sysinfo = (uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL);
    if (!sysinfo || !*sysinfo) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }

    /* Map in the stack frame for the user app */
    err = sos_map_frame(cspace, user_process.stack, user_process.stack_frame, user_process.vspace,
                        stack_bottom, seL4_AllRights, user_process.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return 0;
    }

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return 0;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, user_process.stack, seL4_AllRights);
    if (err != seL4_NoError) {
        cspace_free_slot(cspace, local_stack_cptr);
        ZF_LOGE("Failed to copy cap");
        return 0;
    }

    /* map it into the sos address space */
    err = map_frame(cspace, local_stack_cptr, local_vspace, local_stack_bottom, seL4_AllRights,
                    seL4_ARM_Default_VMAttributes);
    if (err != seL4_NoError) {
        cspace_delete(cspace, local_stack_cptr);
        cspace_free_slot(cspace, local_stack_cptr);
        return 0;
    }

    int index = -2;

    /* null terminate the aux vectors */
    index = stack_write(local_stack_top, index, 0);
    index = stack_write(local_stack_top, index, 0);

    /* write the aux vectors */
    index = stack_write(local_stack_top, index, PAGE_SIZE_4K);
    index = stack_write(local_stack_top, index, AT_PAGESZ);

    index = stack_write(local_stack_top, index, *sysinfo);
    index = stack_write(local_stack_top, index, AT_SYSINFO);

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
        frame_ref_t frame = alloc_frame();
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return 0;
        }

        /* allocate a slot to duplicate the stack frame cap so we can map it into the application */
        seL4_CPtr frame_cptr = cspace_alloc_slot(cspace);
        if (frame_cptr == seL4_CapNull) {
            free_frame(frame);
            ZF_LOGE("Failed to alloc slot for stack extra stack frame");
            return 0;
        }

        /* copy the stack frame cap into the slot */
        err = cspace_copy(cspace, frame_cptr, cspace, frame_page(frame), seL4_AllRights);
        if (err != seL4_NoError) {
            cspace_free_slot(cspace, frame_cptr);
            free_frame(frame);
            ZF_LOGE("Failed to copy cap");
            return 0;
        }

        err = map_frame(cspace, frame_cptr, user_process.vspace, stack_bottom,
                        seL4_AllRights, seL4_ARM_Default_VMAttributes);
        if (err != 0) {
            cspace_delete(cspace, frame_cptr);
            cspace_free_slot(cspace, frame_cptr);
            free_frame(frame);
            ZF_LOGE("Unable to map extra stack frame for user app");
            return 0;
        }
    }

    return stack_top;
}

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * TODO: avoid leaking memory once you implement real processes, otherwise a user
 *       can force your OS to run out of memory by creating lots of failed processes.
 */
bool start_first_process(char *app_name, seL4_CPtr ep)
{
    /* Create a VSpace */
    user_process.vspace_ut = alloc_retype(&user_process.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (user_process.vspace_ut == NULL) {
        return false;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, user_process.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        return false;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &user_process.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        return false;
    }

    /* Initialise the process address space */
    user_process.addrspace = as_create();

    /* Create an IPC buffer */
    user_process.ipc_buffer_ut = alloc_retype(&user_process.ipc_buffer, seL4_ARM_SmallPageObject,
                                                  seL4_PageBits);
    if (user_process.ipc_buffer_ut == NULL) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        return false;
    }

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    seL4_CPtr user_ep = cspace_alloc_slot(&user_process.cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        return false;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&user_process.cspace, user_ep, &cspace, ep, seL4_AllRights, APP_EP_BADGE);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        return false;
    }

    /* Create a new TCB object */
    user_process.tcb_ut = alloc_retype(&user_process.tcb, seL4_TCBObject, seL4_TCBBits);
    if (user_process.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        return false;
    }

    /* Configure the TCB */
    err = seL4_TCB_Configure(user_process.tcb,
                             user_process.cspace.root_cnode, seL4_NilData,
                             user_process.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             user_process.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        return false;
    }

    /* Create scheduling context */
    user_process.sched_context_ut = alloc_retype(&user_process.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (user_process.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        return false;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, user_process.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        return false;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(user_process.tcb, seL4_CapInitThreadTCB, seL4_MinPrio, APP_PRIORITY,
                                  user_process.sched_context, ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        return false;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(user_process.tcb, app_name);

    /* parse the cpio image */
    ZF_LOGI("\nStarting \"%s\"...\n", app_name);
    elf_t elf_file = {};
    unsigned long elf_size;
    size_t cpio_len = _cpio_archive_end - _cpio_archive;
    const char *elf_base = cpio_get_file(_cpio_archive, cpio_len, app_name, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to locate cpio header for %s", app_name);
        return false;
    }
    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        return false;
    }

    /* set up the stack */
    seL4_Word sp = init_process_stack(&cspace, seL4_CapInitThreadVSpace, &elf_file);

    /* set up the heap */
    as_define_heap(user_process.addrspace, &user_process.addrspace->heap_top);

    /* load the elf image from the cpio file */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return false;
    }

    /* Map in the IPC buffer for the thread */
    err = map_frame(&cspace, user_process.ipc_buffer, user_process.vspace, PROCESS_IPC_BUFFER,
                    seL4_AllRights, seL4_ARM_Default_VMAttributes);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        return false;
    }

    /* Start the new process */
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };
    printf("Starting ttytest at %p\n", (void *) context.pc);
    err = seL4_TCB_WriteRegisters(user_process.tcb, 1, 0, 2, &context);
    ZF_LOGE_IF(err, "Failed to write registers");
    return err == seL4_NoError;
}

/* Allocate an endpoint and a notification object for sos.
 * Note that these objects will never be freed, so we do not
 * track the allocated ut objects anywhere
 */
static void sos_ipc_init(seL4_CPtr *ipc_ep, seL4_CPtr *ntfn)
{
    /* Create an notification object for interrupts */
    ut_t *ut = alloc_retype(ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification object");

    /* Bind the notification object to our TCB */
    seL4_Error err = seL4_TCB_BindNotification(seL4_CapInitThreadTCB, *ntfn);
    ZF_LOGF_IFERR(err, "Failed to bind notification object to TCB");

    /* Create an endpoint for user application IPC */
    ut = alloc_retype(ipc_ep, seL4_EndpointObject, seL4_EndpointBits);
    ZF_LOGF_IF(!ut, "No memory for endpoint");
}

/* called by crt */
seL4_CPtr get_seL4_CapInitThreadTCB(void)
{
    return seL4_CapInitThreadTCB;
}

/* tell muslc about our "syscalls", which will be called by muslc on invocations to the c library */
void init_muslc(void)
{
    setbuf(stdout, NULL);

    muslcsys_install_syscall(__NR_set_tid_address, sys_set_tid_address);
    muslcsys_install_syscall(__NR_writev, sys_writev);
    muslcsys_install_syscall(__NR_exit, sys_exit);
    muslcsys_install_syscall(__NR_rt_sigprocmask, sys_rt_sigprocmask);
    muslcsys_install_syscall(__NR_gettid, sys_gettid);
    muslcsys_install_syscall(__NR_getpid, sys_getpid);
    muslcsys_install_syscall(__NR_tgkill, sys_tgkill);
    muslcsys_install_syscall(__NR_tkill, sys_tkill);
    muslcsys_install_syscall(__NR_exit_group, sys_exit_group);
    muslcsys_install_syscall(__NR_ioctl, sys_ioctl);
    muslcsys_install_syscall(__NR_mmap, sys_mmap);
    muslcsys_install_syscall(__NR_brk,  sys_brk);
    muslcsys_install_syscall(__NR_clock_gettime, sys_clock_gettime);
    muslcsys_install_syscall(__NR_nanosleep, sys_nanosleep);
    muslcsys_install_syscall(__NR_getuid, sys_getuid);
    muslcsys_install_syscall(__NR_getgid, sys_getgid);
    muslcsys_install_syscall(__NR_openat, sys_openat);
    muslcsys_install_syscall(__NR_close, sys_close);
    muslcsys_install_syscall(__NR_socket, sys_socket);
    muslcsys_install_syscall(__NR_bind, sys_bind);
    muslcsys_install_syscall(__NR_listen, sys_listen);
    muslcsys_install_syscall(__NR_connect, sys_connect);
    muslcsys_install_syscall(__NR_accept, sys_accept);
    muslcsys_install_syscall(__NR_sendto, sys_sendto);
    muslcsys_install_syscall(__NR_recvfrom, sys_recvfrom);
    muslcsys_install_syscall(__NR_readv, sys_readv);
    muslcsys_install_syscall(__NR_getsockname, sys_getsockname);
    muslcsys_install_syscall(__NR_getpeername, sys_getpeername);
    muslcsys_install_syscall(__NR_fcntl, sys_fcntl);
    muslcsys_install_syscall(__NR_setsockopt, sys_setsockopt);
    muslcsys_install_syscall(__NR_getsockopt, sys_getsockopt);
    muslcsys_install_syscall(__NR_ppoll, sys_ppoll);
    muslcsys_install_syscall(__NR_madvise, sys_madvise);
}

NORETURN void *main_continued(UNUSED void *arg)
{
    /* Initialise other system compenents here */
    seL4_CPtr ipc_ep, ntfn;
    sos_ipc_init(&ipc_ep, &ntfn);
    sos_init_irq_dispatch(
        &cspace,
        seL4_CapIRQControl,
        ntfn,
        IRQ_EP_BADGE,
        IRQ_IDENT_BADGE_BITS
    );

    /* Initialize threads library */
#ifdef CONFIG_SOS_GDB_ENABLED
    /* Create an endpoint that the GDB threads listens to */
    seL4_CPtr gdb_recv_ep;
    ut_t *ep_ut = alloc_retype(&gdb_recv_ep, seL4_EndpointObject, seL4_EndpointBits);
    ZF_LOGF_IF(ep_ut == NULL, "Failed to create GDB endpoint");

    init_threads(ipc_ep, gdb_recv_ep, sched_ctrl_start, sched_ctrl_end);
#else
    init_threads(ipc_ep, ipc_ep, sched_ctrl_start, sched_ctrl_end);
#endif /* CONFIG_SOS_GDB_ENABLED */

    frame_table_init(&cspace, seL4_CapInitThreadVSpace);

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K);

    /* Initialise the network hardware. */
    printf("Network init\n");
    network_init(&cspace, timer_vaddr, ntfn);
    console = network_console_init();
    network_console_register_handler(console, enqueue);
    push_new_file(O_WRONLY, network_console_byte_send, deque, "console"); // initialise stdout
    push_new_file(O_WRONLY, network_console_byte_send, deque, "console"); // initialise stderr

#ifdef CONFIG_SOS_GDB_ENABLED
    /* Initialize the debugger */
    seL4_Error err = debugger_init(&cspace, seL4_CapIRQControl, gdb_recv_ep);
    ZF_LOGF_IF(err, "Failed to initialize debugger %d", err);
#endif /* CONFIG_SOS_GDB_ENABLED */

    /* Initialises the timer */
    printf("Timer init\n");
    start_timer(timer_vaddr);
    /* Sets up the timer irq */
    seL4_IRQHandler irq_handler;
    int init_irq_err = sos_register_irq_handler(meson_timeout_irq(MESON_TIMER_A), true, timer_irq, NULL, &irq_handler);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to initialise IRQ");
    seL4_IRQHandler_Ack(irq_handler);

    /* Start the user application */
    printf("Start first process\n");
    bool success = start_first_process(APP_NAME, ipc_ep);
    ZF_LOGF_IF(!success, "Failed to start first process");

    /* Initialise semaphores for synchronisation and console blocking */
    syscall_sem = malloc(sizeof(sync_bin_sem_t));
    ut_t *sem_ut = alloc_retype(&sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(syscall_sem, sem_cptr, 1);

    /* Creating thread pool */
    initialise_thread_pool(handle_syscall);

    printf("\nSOS entering syscall loop\n");
    syscall_loop(ipc_ep);
}
/*
 * Main entry point - called by crt.
 */
int main(void)
{
    init_muslc();

    /* register the location of the unwind_tables -- this is required for backtrace() to work */
    __register_frame(&__eh_frame_start);

    seL4_BootInfo *boot_info = sel4runtime_bootinfo();

    debug_print_bootinfo(boot_info);

    printf("\nSOS Starting...\n");

    NAME_THREAD(seL4_CapInitThreadTCB, "SOS:root");

    sched_ctrl_start = boot_info->schedcontrol.start;
    sched_ctrl_end = boot_info->schedcontrol.end;

    /* Initialise the cspace manager, ut manager and dma */
    sos_bootstrap(&cspace, boot_info);

    /* switch to the real uart to output (rather than seL4_DebugPutChar, which only works if the
     * kernel is built with support for printing, and is much slower, as each character print
     * goes via the kernel)
     *
     * NOTE we share this uart with the kernel when the kernel is in debug mode. */
    uart_init(&cspace);
    update_vputchar(uart_putchar);

    /* test print */
    printf("SOS Started!\n");

    /* allocate a bigger stack and switch to it -- we'll also have a guard page, which makes it much
     * easier to detect stack overruns */
    seL4_Word vaddr = SOS_STACK;
    for (int i = 0; i < SOS_STACK_PAGES; i++) {
        seL4_CPtr frame_cap;
        ut_t *frame = alloc_retype(&frame_cap, seL4_ARM_SmallPageObject, seL4_PageBits);
        ZF_LOGF_IF(frame == NULL, "Failed to allocate stack page");
        seL4_Error err = map_frame(&cspace, frame_cap, seL4_CapInitThreadVSpace,
                                   vaddr, seL4_AllRights, seL4_ARM_Default_VMAttributes);
        ZF_LOGF_IFERR(err, "Failed to map stack");
        vaddr += PAGE_SIZE_4K;
    }

    utils_run_on_stack((void *) vaddr, main_continued, NULL);

    UNREACHABLE();
}

static void syscall_sos_open(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    ZF_LOGE("syscall: thread example made syscall %d!\n", SYSCALL_SOS_OPEN);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    if (curr_task->msg[1]) {
        user_process.open_len = curr_task->msg[3];
        user_process.curr_len = 0;
        user_process.cache_curr_mode = curr_task->msg[4];
        user_process.cache_curr_path = malloc(user_process.open_len);
    }

    user_process.cache_curr_path[user_process.curr_len++] = curr_task->msg[2];
    if (user_process.curr_len != user_process.open_len) {
        seL4_SetMR(0, -1);
        return;
    }

    int fd;
    if (!strcmp(user_process.cache_curr_path, "console")) {
        if (user_process.cache_curr_mode != O_WRONLY && console_open_for_read) {
            seL4_SetMR(0, -1);
            return;
        }
        sync_bin_sem_wait(syscall_sem);
        console_open_for_read = true;
        fd = push_new_file(user_process.cache_curr_mode, network_console_byte_send,
                           deque, user_process.cache_curr_path);
        sync_bin_sem_post(syscall_sem);
    }
    seL4_SetMR(0, fd);
}

static void syscall_sos_close(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_CLOSE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    sync_bin_sem_wait(syscall_sem);
    struct file *found = pop_file(curr_task->msg[1]);
    sync_bin_sem_post(syscall_sem);
    if (found == NULL) {
        seL4_SetMR(0, -1);
        return;
    } else if (!strcmp(found->path, "console") && found->mode != O_WRONLY) {
        sync_bin_sem_wait(syscall_sem);
        console_open_for_read = false;
        sync_bin_sem_post(syscall_sem);
    }
    free(found->path);
    free(found);
    seL4_SetMR(0, 0);
}

static void syscall_sos_read(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_READ);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive a fd from sos.c */
    int read_fd = curr_task->msg[1];

    sync_bin_sem_wait(syscall_sem);
    struct file *found = find_file(read_fd);
    if (found == NULL || found->mode == O_WRONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
    } else {
        /* Set the reply message to be the return value of the read_handler */
        seL4_SetMR(0, found->read_handler());
    }
    sync_bin_sem_post(syscall_sem);
}

static void syscall_sos_write(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive a fd from sos.c */
    int write_fd = curr_task->msg[1];
    /* Receive a byte from sos.c */
    char receive = curr_task->msg[2];

    sync_bin_sem_wait(syscall_sem);
    struct file *found = find_file(write_fd);
    if (found == NULL || found->mode == O_RDONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
    } else {
        /* Set the reply message to be the return value of the write_handler */
        seL4_SetMR(0, found->write_handler(receive));
    }
    sync_bin_sem_post(syscall_sem);
}

static void syscall_sos_usleep(bool *have_reply, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_USLEEP);
    register_timer(curr_task->msg[1], wakeup, (void *) curr_task);
    *have_reply = false;
}

static void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_TIME_STAMP);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the reply message to be the timestamp since booting in microseconds */
    seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
}

static void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SYS_BRK);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    mem_region_t *curr = user_process.addrspace->regions;
    while (curr != NULL && curr->base != PROCESS_HEAP_START) {
        curr = curr->next;
    }

    uintptr_t newbrk = curr_task->msg[1];
    if (curr == NULL || !newbrk) {
        seL4_SetMR(0, PROCESS_HEAP_START);
    } else {
        curr->size = newbrk - PROCESS_HEAP_START;
        seL4_SetMR(0, user_process.addrspace->heap_top = newbrk);
    }
}

static void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number)
{
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    ZF_LOGE("System call %lu not implemented\n", syscall_number);
    /* Reply -1 to an unimplemented syscall */
    seL4_SetMR(0, -1);
}

static void wakeup(UNUSED uint32_t id, void* data)
{
    struct task *args = (struct task *) data;
    seL4_NBSend(args->reply, seL4_MessageInfo_new(0, 0, 0, 0));
    free_untype(&args->reply, args->reply_ut);
}
