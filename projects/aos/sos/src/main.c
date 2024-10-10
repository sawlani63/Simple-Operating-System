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
#include "thread_pool.h"
#include "addrspace.h"

/* File System */
#include "fs.h"
#include "console.h"


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
#define SYSCALL_SOS_GETDIRENT SYS_getdents64
#define SYSCALL_SOS_STAT SYS_statfs

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

    frame_ref_t ipc_buffer_frame;
    seL4_CPtr ipc_buffer;

    ut_t *sched_context_ut;
    seL4_CPtr sched_context;

    cspace_t cspace;

    frame_ref_t stack_frame;
    seL4_CPtr stack;
    mem_region_t *stack_reg;

    mem_region_t *heap_reg;

    addrspace_t *addrspace;

    fdt *fdt;
} user_process;

struct network_console *console;

bool console_open_for_read = false;

seL4_CPtr nfs_sem_cptr;
sync_bin_sem_t *nfs_sem = NULL;

seL4_CPtr sem_cptr;
sync_bin_sem_t *syscall_sem = NULL;

struct arg_struct {
    open_file *file;
    int err;
};

bool handle_vm_fault(seL4_Word fault_addr);

static void syscall_sos_open(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_close(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_read(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_write(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_usleep(bool *have_reply, struct task *curr_task);
static void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg);
static void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, struct task *curr_task);
static void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number);
static void wakeup(UNUSED uint32_t id, void *data);
static void nfs_open_cb(int err, struct nfs_context *nfs, void *data, void *private_data);
static void nfs_close_cb(int err, struct nfs_context *nfs, void *data, void *private_data);
static void nfs_read_cb(int err, struct nfs_context *nfs, void *data, void *private_data);
static void nfs_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data);

static frame_ref_t l4_frame(pt_entry *l4_pt, uint16_t l4_index) {
    return (frame_ref_t )(l4_pt[l4_index] & MASK(9));
}

static bool vaddr_is_mapped(seL4_Word vaddr) {
    /* We assume the top level is mapped. */
    page_upper_directory *l1_pt = user_process.addrspace->page_table;

    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */

    page_directory *l2_pt = l1_pt[l1_index].l2;
    if (l2_pt == NULL) {
        return false;
    }

    page_table *l3_pt = l2_pt[l2_index].l3;
    if (l3_pt == NULL) {
        return false;
    }

    pt_entry *l4_pt = l3_pt[l3_index].l4;
    if (l4_pt == NULL) {
        return false;
    }

    if ((frame_ref_t )(l4_pt[l4_index] & MASK(19)) == NULL_FRAME) {
        return false;
    }

    return true;
}

static bool vaddr_check(seL4_Word vaddr) {
    /* If the vaddr is not in a valid region we error out. Then if the address is not already
     * mapped and vm_fault returns an error when trying to map it, we also error out.*/
    return vaddr_is_mapped(vaddr) || handle_vm_fault(vaddr);
}

static bool loop_vaddr_check(seL4_Word vaddr, size_t len) {
    size_t bytes_left = len;
    int offset = vaddr & (PAGE_SIZE_4K - 1);

    /* Check all the necessary vaddrs per frame. */
    while (bytes_left > 0) {
        size_t update = bytes_left > (PAGE_SIZE_4K - offset) ? (PAGE_SIZE_4K - offset) : bytes_left;

        if (!vaddr_check(vaddr)) {
            return false;
        }

        /* Update offset, virtual address, and bytes left */
        offset = 0;
        vaddr += update;
        bytes_left -= update;
    }

    return true;
}

bool handle_vm_fault(seL4_Word fault_addr) {
    addrspace_t *as = user_process.addrspace;

    if (as == NULL || as->page_table == NULL || fault_addr == 0) {
        ZF_LOGE("Encountered a weird error where one of the given addresses was null");
        return false;
    }

    /* We use our shadow page table which follows the same structure as the hardware one.
     * Check the seL4 Manual section 7.1.1 for hardware virtual memory objects. Importantly
     * the top-most 16 bits of the virtual address are unused bits, so we ignore them. */
    uint16_t l1_index = (fault_addr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (fault_addr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (fault_addr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (fault_addr >> 12) & MASK(9); /* Next 9 bits */

    /* Cache the related page table entries so we don't have to perform lots of dereferencing. */
    page_upper_directory *l1_pt = as->page_table;
    page_directory *l2_pt = NULL;
    page_table *l3_pt = NULL;
    pt_entry *l4_pt = NULL;
    if (l1_pt[l1_index].l2 != NULL) {
        l2_pt = l1_pt[l1_index].l2;
        if (l2_pt[l2_index].l3 != NULL) {
            l3_pt = l2_pt[l2_index].l3;
            if (l3_pt[l3_index].l4 != NULL) {
                l4_pt = l3_pt[l3_index].l4;
            }
        }
    }

    seL4_ARM_VMAttributes attr = seL4_ARM_Default_VMAttributes;

    /* If there already exists a valid entry in our page table, reload the Hardware Page Table and
     * unblock the caller with an empty message. */
    if (l4_pt != NULL && l4_frame(l4_pt, l4_index) != NULL_FRAME) {
        pt_entry entry = l4_pt[l4_index];
        if (!debug_is_read_fault() && ((entry >> 31) & REGION_WR) == 0) {
            ZF_LOGE("Trying to write to a read only page");
            return false;
        }
        /* Assign the appropriate rights for the frame we are about to map. */
        seL4_CapRights_t rights = seL4_CapRights_new(0, 0, (entry >> 31) & REGION_RD, (entry >> 32) & 1);
        if (!((entry >> 31) & REGION_EX)) {
            attr |= seL4_ARM_ExecuteNever;
        }
        if (map_frame_impl(&cspace, l4_frame(l4_pt, l4_index), user_process.vspace, fault_addr,
                           rights, attr, NULL, NULL, NULL) != 0) {
            ZF_LOGE("Could not map the frame into the two page tables");
            return false;
        }
        return true;
    }

    /* Check if we're faulting in a valid region. */
    mem_region_t *reg;
    seL4_Word heap_top = user_process.heap_reg->base + user_process.heap_reg->size;
    for (reg = as->regions; reg != NULL; reg = reg->next) {
        seL4_Word top_of_region = reg->base + reg->size;
        if (fault_addr >= reg->base && fault_addr < top_of_region) {
            /* We need this permissions check for demand paging that will later occur on the Hardware
            * Page Table. In the case a page in the HPT gets swapped to disk yet remains on the
            * Shadow Page Table, we need some way to know if the user is allowed to write to it. */
            if (!debug_is_read_fault() && (reg->perms & REGION_WR) == 0) {
                ZF_LOGE("Trying to write to a read only page");
                return false;
            }
            /* Fault occurred in a valid region and permissions line up so we can safely break out. */
            break;
        } else if (top_of_region == PROCESS_STACK_TOP
                   && fault_addr < top_of_region && ALIGN_DOWN(fault_addr, PAGE_SIZE_4K) >= heap_top) {
            /* Expand the stack. */
            reg->base = fault_addr;
            reg->size = PROCESS_STACK_TOP - fault_addr;
            break;
        }
    }

    if (reg == NULL) {
        ZF_LOGE("Could not find a valid region for this address");
        return false;
    }

    /* Allocate any necessary levels within the shadow page table. */
    if (l2_pt == NULL) {
        l2_pt = l1_pt[l1_index].l2 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_directory));
        if (l2_pt == NULL) {
            ZF_LOGE("Failed to allocate level 2 page table");
            return false;
        }
    }
    if (l3_pt == NULL) {
        l3_pt = l2_pt[l2_index].l3 = calloc(PAGE_TABLE_ENTRIES, sizeof(page_table));
        if (l3_pt == NULL) {
            ZF_LOGE("Failed to allocate level 3 page table");
            return false;
        }
    }
    if (l4_pt == NULL) {
        l4_pt = l3_pt[l3_index].l4 = calloc(PAGE_TABLE_ENTRIES, sizeof(pt_entry));
        if (l4_pt == NULL) {
            ZF_LOGE("Failed to allocate level 4 page table");
            return false;
        }
    }

    /* Assign the appropriate rights for the frame we are about to map. */
    seL4_CapRights_t rights = seL4_CapRights_new(0, 0, reg->perms & REGION_RD, (reg->perms >> 1) & 1);
    if (!(reg->perms & REGION_EX)) {
        attr |= seL4_ARM_ExecuteNever;
    }

    /* Allocate a new frame to be mapped by the shadow page table. */
    frame_ref_t frame_ref = alloc_frame();
    if (frame_ref == NULL_FRAME) {
        ZF_LOGE("Failed to allocate a frame");
        return false;
    }
    l4_pt[l4_index] = frame_ref | (reg->perms << 31);

    /* Map the frame into the relevant page tables. */
    if (sos_map_frame_impl(&cspace, user_process.vspace, fault_addr, rights, attr, frame_ref, l1_pt, l4_pt) != 0) {
        ZF_LOGE("Could not map the frame into the two page tables");
        return false;
    }

    return true;
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
        case SYSCALL_SOS_GETDIRENT:
            syscall_sos_getdirent(&reply_msg, curr_task);
            break;
        case SYSCALL_SOS_STAT:
            syscall_sos_stat(&reply_msg, curr_task);
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
                = {seL4_GetMR(0), seL4_GetMR(1), seL4_GetMR(2), seL4_GetMR(3)};
            memcpy(task.msg, msg, sizeof(seL4_Word) * NUM_MSG_REGISTERS);
            submit_task(task);
            
            /* To stop the main thread from overwriting the worker thread's
             * reply object, we give the main thread a new one */
            reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
            if (reply_ut == NULL) {
                ZF_LOGF("Failed to alloc reply object ut");
            }
        } else if (label == seL4_Fault_VMFault) {
            if (handle_vm_fault(seL4_GetMR(seL4_VMFault_Addr))) {
                /* Respond with an empty message just to unblock the caller. */
                seL4_NBSend(reply, seL4_MessageInfo_new(0, 0, 0, 0));
            }
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
    /* Allocating a region for the stack */
    user_process.stack_reg = as_define_stack(user_process.addrspace);
    if (user_process.stack_reg == NULL) {
        ZF_LOGD("Failed to alloc stack region");
        return -1;
    }

    /* Create a stack frame */
    user_process.stack_frame = alloc_frame();
    if (user_process.stack_frame == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return -1;
    }
    user_process.stack = frame_page(user_process.stack_frame);

    /* virtual addresses in the target process' address space */
    uintptr_t stack_top = PROCESS_STACK_TOP;
    uintptr_t stack_bottom = PROCESS_STACK_TOP - PAGE_SIZE_4K;
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
    seL4_Error err = sos_map_frame(cspace, user_process.vspace, stack_bottom, seL4_AllRights,
                                   seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever,
                                   user_process.stack_frame, user_process.addrspace);
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

        err = sos_map_frame(cspace, user_process.vspace, stack_bottom, seL4_AllRights,
                            seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever, frame,
                            user_process.addrspace);
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
    user_process.ipc_buffer_frame = alloc_frame();
    if (user_process.ipc_buffer_frame == NULL_FRAME) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        return false;
    }
    user_process.ipc_buffer = frame_page(user_process.ipc_buffer_frame);

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

    /* Allocating a region for the heap */
    user_process.heap_reg = as_define_heap(user_process.addrspace);
    if (user_process.stack_reg == NULL) {
        ZF_LOGD("Failed to alloc heap region");
        return false;
    }

    /* load the elf image from the cpio file */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return false;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, user_process.vspace, PROCESS_IPC_BUFFER, seL4_AllRights,
                        seL4_ARM_Default_VMAttributes | seL4_ARM_ExecuteNever,
                        user_process.ipc_buffer_frame, user_process.addrspace);
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

    /* Initialise the per-process file descriptor table */
    char err;
    user_process.fdt = fdt_create(&err);
    ZF_LOGF_IF(err, "Failed to initialise the per-process file descriptor table");

    /* Initialise the network hardware. */
    printf("Network init\n");
    nfs_sem = malloc(sizeof(sync_bin_sem_t));
    ut_t *nfs_sem_ut = alloc_retype(&nfs_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!nfs_sem_ut, "No memory for notification");
    sync_bin_sem_init(nfs_sem, nfs_sem_cptr, 0);

    network_init(&cspace, timer_vaddr, ntfn, nfs_sem);
    console = network_console_init();
    network_console_register_handler(console, enqueue);
    init_console_sem();
    
    //nfs_open_file("console", O_WRONLY | 0100, nfs_open_cb, NULL);  //think how to do this while nfs mounts
    open_file *file = file_create("console", O_WRONLY, NULL);
    uint32_t fd;
    err = fdt_put(user_process.fdt, file, &fd); // initialise stdout
    ZF_LOGF_IF(err, "No memory for new file object");
    err = fdt_put(user_process.fdt, file, &fd); // initialise stderr
    ZF_LOGF_IF(err, "No memory for new file object");

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

    init_irq_err = sos_register_irq_handler(meson_timeout_irq(MESON_TIMER_B), true, timer_irq, NULL, &irq_handler);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to initialise IRQ");
    seL4_IRQHandler_Ack(irq_handler);

    /* Start the user application */
    printf("Start first process\n");
    bool success = start_first_process(APP_NAME, ipc_ep);
    ZF_LOGF_IF(!success, "Failed to start first process");

    /* Initialise semaphores for synchronisation and console blocking */
    syscall_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!syscall_sem, "No memory for semaphore object");
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

static frame_ref_t get_frame(seL4_Word vaddr) {
    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    return l4_frame(user_process.addrspace->page_table[l1_index].l2[l2_index].l3[l3_index].l4,
                    l4_index);
    }

static void syscall_sos_open(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    /* Wait for the nfs to be mounted before continuing with open. */
    sync_bin_sem_wait(nfs_sem);
    sync_bin_sem_post(nfs_sem);

    ZF_LOGE("syscall: thread example made syscall %d!\n", SYSCALL_SOS_OPEN);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    seL4_Word vaddr = curr_task->msg[1];
    int path_len = curr_task->msg[2];
    sync_bin_sem_wait(syscall_sem);
    if (!loop_vaddr_check(vaddr, path_len)) {
        sync_bin_sem_post(syscall_sem);
        seL4_SetMR(0, -1);
        return;
    }
    sync_bin_sem_post(syscall_sem);
    int mode = curr_task->msg[3];
    if ((mode != O_WRONLY) && (mode != O_RDONLY) && (mode != O_RDWR)) {
        seL4_SetMR(0, -1);
        return;
    }

    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);
    size_t bytes_left = path_len;

    char *file_path = (char *) calloc(path_len, sizeof(char));
    sync_bin_sem_wait(syscall_sem);

    while (bytes_left > 0) {
        size_t len = bytes_left > (PAGE_SIZE_4K - offset) ? (PAGE_SIZE_4K - offset) : bytes_left;

        if (!vaddr_check(vaddr)) {
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }
        char *data = (char *) frame_data(get_frame(vaddr));
        strcat(file_path, data + offset);

        vaddr += len;
        offset = 0;
        bytes_left -= len;
    }

    seL4_CPtr file_sem_cptr;
    sync_bin_sem_t *file_sem = malloc(sizeof(sync_bin_sem_t));
    ut_t *file_sem_ut = alloc_retype(&file_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!file_sem_ut, "No memory for notification");
    sync_bin_sem_init(file_sem, file_sem_cptr, 1);

    open_file *file = file_create(file_path, mode, file_sem);
    struct arg_struct args;
    args.file = file;
    args.err = 0;
    if (!strcmp("console", file_path)) {
        if (console_open_for_read && mode != O_WRONLY) {
            // destroy file if not auto freed
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        } else if (!console_open_for_read && mode != O_WRONLY) {
            console_open_for_read = true;
        }
    } else {
        sync_bin_sem_wait(file->sem);
        if (nfs_open_file(file_path, mode, nfs_open_cb, &args)) {
            // destroy file if not auto freed
            sync_bin_sem_post(file->sem);
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }
        sync_bin_sem_wait(file->sem);
        if (args.err) {
            // destroy file if not auto freed
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }
    }

    uint32_t fd;
    char err = fdt_put(user_process.fdt, file, &fd);
    sync_bin_sem_post(syscall_sem);

    seL4_SetMR(0, err ? -1 : (int) fd);
}

static void syscall_sos_close(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_CLOSE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    sync_bin_sem_wait(syscall_sem);
    open_file *found = fdt_get_file(user_process.fdt, curr_task->msg[1]);
    if (found == NULL) {
        sync_bin_sem_post(syscall_sem);
        seL4_SetMR(0, -1);
        return;
    } else if (!strcmp(found->path, "console") && found->mode != O_WRONLY) {
        console_open_for_read = false;
    } else {
        struct arg_struct args;
        args.file = found;
        args.err = 0;
        sync_bin_sem_wait(found->sem);
        if (nfs_close_file(found->nfsfh, nfs_close_cb, &args)) {
            sync_bin_sem_post(found->sem);
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }
        sync_bin_sem_wait(found->sem);
        if (args.err) {
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }
    }
    fdt_remove(user_process.fdt, curr_task->msg[1]);
    sync_bin_sem_post(syscall_sem);
    seL4_SetMR(0, 0);
}

static void syscall_sos_read(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_READ);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive a fd from sos.c */
    int read_fd = curr_task->msg[1];
    seL4_Word vaddr = curr_task->msg[2];
    int nbyte = curr_task->msg[3];
    sync_bin_sem_wait(syscall_sem);
    if (!loop_vaddr_check(vaddr, nbyte)) {
        sync_bin_sem_post(syscall_sem);
        seL4_SetMR(0, -1);
        return;
    }

    open_file *found = fdt_get_file(user_process.fdt, read_fd);
    if (found == NULL || found->mode == O_WRONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
    } else {
        int is_console = file_is_console(found);
        /* Perform the read operation. We don't assume that the buffer is only 1 frame long. */
        uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);
        if (!is_console) {
            char *data = (char *)frame_data(get_frame(vaddr));
            uint16_t i;
            for (i = 0; i < nbyte; i++) {
                if (i + offset >= PAGE_SIZE_4K) {
                    data = (char *)frame_data(get_frame(vaddr));
                    offset = 0;
                }

                /* Write to data buffer */
                char recv = deque();
                data[i + offset] = recv;
                if (recv == '\n') {
                    i++;
                    break;
                }
            }

            /* Set the reply message to be the return value of the read_handler */
            seL4_SetMR(0, i);
        } else {
            size_t bytes_left = nbyte;
            struct arg_struct args;
            args.file = found;
            args.err = 0;
            while (bytes_left > 0) {
                size_t len = bytes_left > (PAGE_SIZE_4K - offset) ? (PAGE_SIZE_4K - offset) : bytes_left;
                
                if (!vaddr_check(vaddr)) {
                    sync_bin_sem_post(syscall_sem);
                    seL4_SetMR(0, -1);
                    return;
                }

                char *data = (char *)frame_data(get_frame(vaddr));

                sync_bin_sem_wait(found->sem);
                if (nfs_read_file(found->nfsfh, len, nfs_read_cb, &args)) {
                    sync_bin_sem_post(found->sem);
                    sync_bin_sem_post(syscall_sem);
                    seL4_SetMR(0, -1);
                    return;
                }
                sync_bin_sem_wait(found->sem);
                if (args.err <= 0) {
                    sync_bin_sem_post(syscall_sem);
                    seL4_SetMR(0, -1);
                    return;
                }
                for (int i = 0; i < args.err; i++) {
                    data[i + offset] = found->read_buffer[i];
                } //to be safe, improve this later
                offset = 0;
                vaddr += args.err;
                bytes_left -= args.err;
            }
            seL4_SetMR(0, nbyte - bytes_left);
        }
    }
    sync_bin_sem_post(syscall_sem);
}

static void syscall_sos_write(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* Construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    /* Receive fd, virtual address, and number of bytes from sos.c */
    int write_fd = curr_task->msg[1];
    seL4_Word vaddr = curr_task->msg[2];
    size_t nbyte = curr_task->msg[3];

    /* Find the file associated with the file descriptor */
    sync_bin_sem_wait(syscall_sem);
    open_file *found = fdt_get_file(user_process.fdt, write_fd);
    if (found == NULL || found->mode == O_RDONLY) {
        /* Set the reply message to be an error value and return early */
        sync_bin_sem_post(syscall_sem);
        seL4_SetMR(0, -1);
        return;
    }

    size_t bytes_left = nbyte;
    int offset = vaddr & (PAGE_SIZE_4K - 1);
    int is_console = file_is_console(found);

    struct arg_struct args;
    args.file = found;
    args.err = 0;

    /* Perform the write operation. We don't assume that the buffer is only 1 frame long. */
    while (bytes_left > 0) {
        size_t len = bytes_left > (PAGE_SIZE_4K - offset) ? (PAGE_SIZE_4K - offset) : bytes_left;
        
        if (!vaddr_check(vaddr)) {
            sync_bin_sem_post(syscall_sem);
            seL4_SetMR(0, -1);
            return;
        }

        char *data = (char *)frame_data(get_frame(vaddr));

        if (!is_console) {
            int err = network_console_send(data + offset, len);
            if (err < 0) {
                sync_bin_sem_post(syscall_sem);
                seL4_SetMR(0, -1);
                return;
            }
            vaddr += err;
            bytes_left -= err;
        } else {
            /* Write data */
            sync_bin_sem_wait(found->sem);
            if (nfs_write_file(found->nfsfh, len, data + offset, nfs_write_cb, &args)) {
                sync_bin_sem_post(found->sem);
                sync_bin_sem_post(syscall_sem);
                seL4_SetMR(0, -1);
                return;
            }
            sync_bin_sem_wait(found->sem);
            if (args.err <= 0) {
                sync_bin_sem_post(syscall_sem);
                seL4_SetMR(0, -1);
                return;
            }
            vaddr += args.err;
            bytes_left -= args.err;
        }

        /* Update offset, virtual address, and bytes left */
        offset = 0;
    }
    sync_bin_sem_post(syscall_sem);

    /* Set the reply message to the number of bytes written */
    seL4_SetMR(0, nbyte - bytes_left);
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

    sync_bin_sem_wait(syscall_sem);
    uintptr_t newbrk = curr_task->msg[1];
    if (newbrk <= 0) {
        seL4_SetMR(0, PROCESS_HEAP_START);        
    } else if (newbrk >= ALIGN_DOWN(user_process.stack_reg->base, PAGE_SIZE_4K)) {
        seL4_SetMR(0, 0);
    } else {
        user_process.heap_reg->size = newbrk - PROCESS_HEAP_START;
        seL4_SetMR(0, newbrk);
    }
    sync_bin_sem_post(syscall_sem);
}

static void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    
}

static void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_STAT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word path_vaddr = curr_task->msg[1];
    seL4_Word buf_vaddr = curr_task->msg[2];

    uint16_t offset1 = path_vaddr & (PAGE_SIZE_4K - 1);
    uint16_t offset2 = buf_vaddr & (PAGE_SIZE_4K - 1);
    size_t path_bytes = curr_task->msg[3];
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

static void nfs_open_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data)
{
    struct arg_struct *args = (struct arg_struct *) private_data;
    open_file *file = args->file;
    if (err) {
        ZF_LOGE("NFS: Error in opening file, %s\n", (char*) data);
    } else {
        nfsfh_init(file, data);
    }
    args->err = err;
    sync_bin_sem_post(file->sem);
    sync_bin_sem_post(file->sem);
}

static void nfs_close_cb(int err, struct nfs_context *nfs, void *data, void *private_data)
{
    struct arg_struct *args = (struct arg_struct *) private_data;
    open_file *file = args->file;
    if (err) {
        ZF_LOGE("NFS: Error in closing file, %s\n", (char*) data);
    }
    args->err = err;
    sync_bin_sem_post(file->sem);
    sync_bin_sem_post(file->sem);
}

static void nfs_read_cb(int err, struct nfs_context *nfs, void *data, void *private_data)
{
    struct arg_struct *args = (struct arg_struct *) private_data;
    open_file *file = args->file;
    if (err < 0) {
        ZF_LOGE("NFS: Error in reading file, %s\n", (char*) data);
    } else {
        file->read_buffer = (char*) data;
    }
    args->err = err;
    sync_bin_sem_post(file->sem);
    sync_bin_sem_post(file->sem);
}

static void nfs_write_cb(int err, UNUSED struct nfs_context *nfs, void *data, void *private_data)
{
    struct arg_struct *args = (struct arg_struct *) private_data;
    open_file *file = args->file;
    if (err < 0) {
        ZF_LOGE("NFS: Error in writing file, %s\n", (char*) data);
    }
    args->err = err;
    sync_bin_sem_post(file->sem);
    sync_bin_sem_post(file->sem);
}
