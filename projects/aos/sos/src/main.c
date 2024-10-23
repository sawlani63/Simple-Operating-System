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
#include "clock_replacement.h"

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

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

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

struct user_process user_process;

struct network_console *console;

extern sync_bin_sem_t *nfs_sem;

open_file *nfs_pagefile;

bool handle_vm_fault(seL4_Word fault_addr) {
    addrspace_t *as = user_process.addrspace;

    if (as == NULL || as->page_table == NULL || fault_addr == 0) {
        ZF_LOGE("Encountered a weird error where one of the given addresses was null");
        return false;
    }

    /* Check if we're faulting in a valid region. */
    mem_region_t *reg;
    if (fault_addr < as->stack_reg->base
        && ALIGN_DOWN(fault_addr, PAGE_SIZE_4K) >= as->below_stack->base + as->below_stack->size) {
        /* Expand the stack. */
        as->stack_reg->base = ALIGN_DOWN(fault_addr, PAGE_SIZE_4K);
        as->stack_reg->size = PROCESS_STACK_TOP - ALIGN_DOWN(fault_addr, PAGE_SIZE_4K);
        reg = as->stack_reg;
    } else {
        mem_region_t tmp = { .base = fault_addr };
        reg = sglib_mem_region_t_find_closest_member(as->region_tree, &tmp);
        if (reg != NULL && fault_addr < reg->base + reg->size) {
            // Check permissions for write faults
            if (!debug_is_read_fault() && (reg->perms & REGION_WR) == 0) {
                ZF_LOGE("Trying to write to a read only page");
                return false;
            }
        } else {
            ZF_LOGE("Could not find a valid region for this address: %p", (void*) fault_addr);
            return false;
        }
    }

    /* Allocate a new frame to be mapped by the shadow page table. */
    frame_ref_t frame_ref = clock_alloc_frame(fault_addr);
    if (frame_ref == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return false;
    }

    uint16_t l1_index = (fault_addr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (fault_addr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (fault_addr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (fault_addr >> 12) & MASK(9); /* Next 9 bits */

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

    if (l4_pt != NULL && l4_pt[l4_index].swapped == 1) {
        uint64_t file_offset = l4_pt[l4_index].swap_map_index * PAGE_SIZE_4K;
        char *data = (char *)frame_data(frame_ref);
        nfs_args args = {PAGE_SIZE_4K, data, nfs_sem};
        int res = nfs_pread_file(nfs_pagefile->handle, file_offset, PAGE_SIZE_4K, nfs_async_read_cb, &args);
        if (res < (int)PAGE_SIZE_4K) {
            return false;
        }
        
        mark_block_free(file_offset / PAGE_SIZE_4K);
    }

    /* Map the frame into the relevant page tables. */
    if (sos_map_frame(&cspace, user_process.vspace, fault_addr, reg->perms, frame_ref, as) != 0) {
        ZF_LOGE("Could not map the frame into the two page tables");
        return false;
    }

    return true;
}

/**
 * Deals with a syscall and sets the message registers before returning the
 * message info to be passed through to seL4_ReplyRecv()
 */
seL4_MessageInfo_t handle_syscall()
{
    seL4_MessageInfo_t reply_msg;

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    /* Process system call */
    switch (syscall_number) {
    case SYSCALL_SOS_OPEN:
        syscall_sos_open(&reply_msg);
        break;
    case SYSCALL_SOS_CLOSE:
        syscall_sos_close(&reply_msg);
        break;
    case SYSCALL_SOS_READ:
        syscall_sos_read(&reply_msg);
        break;
    case SYSCALL_SOS_WRITE:
        syscall_sos_write(&reply_msg);
        break;
    case SYSCALL_SOS_USLEEP:
        syscall_sos_usleep(&reply_msg);
        break;
    case SYSCALL_SOS_TIME_STAMP:
        syscall_sos_time_stamp(&reply_msg);
        break;
    case SYSCALL_SYS_BRK:
        syscall_sys_brk(&reply_msg);
        break;
    case SYSCALL_SOS_STAT:
        syscall_sos_stat(&reply_msg);
        break;
    case SYSCALL_SOS_GETDIRENT:
        syscall_sos_getdirent(&reply_msg);
        break;
    case SYSCALL_SYS_MMAP:
        syscall_sys_mmap(&reply_msg);
        break;
    case SYSCALL_SYS_MUNMAP:
        syscall_sys_munmap(&reply_msg);
        break;
    default:
        syscall_unknown_syscall(&reply_msg, syscall_number);
    }

    return reply_msg;
}

NORETURN void syscall_loop(void *arg)
{
    seL4_CPtr ep = (seL4_CPtr) arg;
    seL4_CPtr reply;

    /* Create reply object */
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }

    bool have_reply = false;
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    while (1) {
        seL4_MessageInfo_t message;

        /* Reply (if there is a reply) and block on ep, waiting for an IPC sent over ep */
        if (have_reply) {
            message = seL4_ReplyRecv(ep, reply_msg, 0, reply);
        } else {
            message = seL4_Recv(ep, 0, reply);
        }

        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);

        if (label == seL4_Fault_NullFault) {
            /* It's not a fault or an interrupt, it must be an IPC
             * message from console_test! */
            reply_msg = handle_syscall();
            have_reply = true;
        } else if (label == seL4_Fault_VMFault) {
            reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);
            have_reply = handle_vm_fault(seL4_GetMR(seL4_VMFault_Addr));
        } else {
            /* some kind of fault */
            debug_print_fault(message, APP_NAME);
            /* dump registers too */
            debug_dump_registers(user_process.tcb);
            /* Don't reply and recv on nothing */
            have_reply = false;

            ZF_LOGF("The SOS skeleton does not know how to handle faults!");
        }
    }
}

NORETURN void irq_loop(void *ipc_ep)
{
    seL4_CPtr ep = (seL4_CPtr) ipc_ep;
    seL4_CPtr reply;

    /* Create reply object */
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }

    while (1) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t message = seL4_Recv(ep, &badge, reply);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification object! */
            sos_handle_irq_notification(&badge, 0);
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
    user_process.addrspace->stack_reg = as_define_stack(user_process.addrspace);
    if (user_process.addrspace->stack_reg == NULL) {
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
    user_process.stack_frame = clock_alloc_frame(stack_bottom);
    if (user_process.stack_frame == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return -1;
    }
    user_process.stack = frame_page(user_process.stack_frame);

    /* find the vsyscall table */
    uintptr_t *sysinfo = (uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL);
    if (!sysinfo || !*sysinfo) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }

    /* Map in the stack frame for the user app */
    seL4_Error err = sos_map_frame(cspace, user_process.vspace, stack_bottom, REGION_RD | REGION_WR,
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
        frame_ref_t frame = clock_alloc_frame(stack_bottom);
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return 0;
        }

        err = sos_map_frame(cspace, user_process.vspace, stack_bottom,
                            REGION_RD | REGION_WR, frame, user_process.addrspace);
    }

    return stack_top;
}

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * TODO: avoid leaking memory once you implement real processes, otherwise a user
 *       can force your OS to run out of memory by creating lots of failed processes.
 */
bool start_first_process(char *app_name)
{
    seL4_CPtr ep;
    ut_t *ut = alloc_retype(&ep, seL4_EndpointObject, seL4_EndpointBits);
    if (!ut) {
        ZF_LOGF_IF(!ut, "No memory for endpoint");
        return false;
    }

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

    as_define_ipc_buff(user_process.addrspace);

    /* Create an IPC buffer */
    user_process.ipc_buffer_frame = clock_alloc_frame(PROCESS_IPC_BUFFER);
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
    user_process.addrspace->heap_reg = as_define_heap(user_process.addrspace);
    if (user_process.addrspace->heap_reg == NULL) {
        ZF_LOGD("Failed to alloc heap region");
        return false;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, user_process.vspace, PROCESS_IPC_BUFFER, REGION_RD | REGION_WR,
                        user_process.ipc_buffer_frame, user_process.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        return false;
    }

    /* load the elf image from the cpio file */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        return false;
    }

    init_threads(ep, ep, sched_ctrl_start, sched_ctrl_end);
    sos_thread_t *handler_thread = thread_create(syscall_loop, (void *)ep, 0, true, seL4_MaxPrio, seL4_CapNull, true);
    if (handler_thread == NULL) {
        ZF_LOGE("Could not create system call handler thread for %s\n", app_name);
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

    /* Initialise semaphores for synchronisation */
    init_nfs_sem();
    init_semaphores();

    /*irq_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!irq_sem, "No memory for semaphore object");
    ut_t *irq_ut = alloc_retype(&irq_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!irq_ut, "No memory for notification");
    sync_bin_sem_init(irq_sem, irq_sem_cptr, 0);*/

    /* Initialise the network hardware. */
    printf("Network init\n");

    network_init(&cspace, timer_vaddr, ntfn);
    console = network_console_init();
    network_console_register_handler(console, enqueue);
    init_console_sem();

    /* After the main thread is done handling irqs in network_init, unbind the notification object from the main thread's TCB */
    seL4_Error bind_err = seL4_TCB_UnbindNotification(seL4_CapInitThreadTCB);
    ZF_LOGF_IFERR(err, "Failed to unbind notification object");
    /* Initialize a temporary irq handling thread that binds the notification object to its TCB and handles irqs until the main thread is done with its tasks */
    sos_thread_t *irq_temp_thread = thread_create(irq_loop, (void *)ipc_ep, 0, true, seL4_MaxPrio, ntfn, false);
    if (irq_temp_thread == NULL) {
        ZF_LOGE("Could not create irq handler thread\n");
    }
    
    open_file *file = file_create("console", O_WRONLY, network_console_send, deque);
    uint32_t fd;
    err = fdt_put(user_process.fdt, file, &fd); // initialise stdout
    ZF_LOGF_IF(err, "No memory for new file object");
    err = fdt_put(user_process.fdt, file, &fd); // initialise stderr
    ZF_LOGF_IF(err, "No memory for new file object");

    nfs_pagefile = file_create("pagefile", O_RDWR, nfs_write_file, nfs_read_file);
    nfs_args args = {.sem = nfs_sem};
    /* Wait for NFS to finish mounting */
    sync_bin_sem_wait(nfs_sem);
    /* Open the pagefile on NFS so we can read/write to/from it for demand paging */
    int error = nfs_open_file("pagefile", O_RDWR, nfs_async_open_cb, &args);
    ZF_LOGF_IF(error, "NFS: Error in opening pagefile");
    nfs_pagefile->handle = args.buff;

    init_bitmap();

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
    bool success = start_first_process(APP_NAME);
    ZF_LOGF_IF(!success, "Failed to start first process");

    /* Creating thread pool */
    // initialise_thread_pool(handle_syscall);

    /* Since our main thread has no other tasks left, we swap the task of irq handling from the temp thread to our main thread, and destroy our temp thread */
    seL4_TCB_UnbindNotification(irq_temp_thread->tcb);
    //error = thread_destroy(irq_temp_thread); gets stuck somewhere (inconsistent)
    ZF_LOGF_IFERR(error, "Failed to destroy the temp irq thread");
    bind_err = seL4_TCB_BindNotification(seL4_CapInitThreadTCB, ntfn);
    ZF_LOGF_IFERR(bind_err, "Failed to bind notification object to TCB");
    printf("\nSOS entering syscall loop\n");
    /* Continue with the syscall */
    //sync_bin_sem_post(irq_sem);
    irq_loop((void *) ipc_ep);
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