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

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <cspace/cspace.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>
#include <sel4runtime.h>
#include <sel4runtime/auxv.h>
#include <aos/sel4_zf_logif.h>
#include <aos/debug.h>
#include <autoconf.h>
#include <utils/util.h>
#include <aos/vsyscall.h>
#include <clock/clock.h>

#include "vmem_layout.h"
#include "process.h"
#include "sos_syscall.h"
#include "frame_table.h"
#include "tests.h"
#include "syscalls.h"
#include "console.h"
#include "bootstrap.h"
#include "irq.h"
#include "drivers/uart.h"
#include "mapping.h"
#include "clock_replacement.h"
#include "buffercache.h"
#include "dentry.h"

#include "boot_driver.h"
#include "sharedvm.h"

#include <sos/gen_config.h>
#ifdef CONFIG_SOS_GDB_ENABLED
#include "debugger.h"
#endif /* CONFIG_SOS_GDB_ENABLED */

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

extern char __eh_frame_start[];
/* provided by gcc */
extern void (__register_frame)(void *);

/* root tasks cspace */
cspace_t cspace;

seL4_CPtr sched_ctrl_start;
seL4_CPtr sched_ctrl_end;
sync_bin_sem_t *cspace_sem = NULL;

extern user_process_t *user_process_list;
extern sync_bin_sem_t *process_list_sem;
struct network_console *console;

extern seL4_CPtr nfs_signal;

open_file *nfs_pagefile;

seL4_CPtr clock_driver_ep;

bool handle_vm_fault(seL4_Word fault_addr, seL4_Word badge) {
    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);
    addrspace_t *as = user_process.addrspace;

    if (as == NULL || as->page_table == NULL || fault_addr == 0) {
        ZF_LOGE("Encountered a weird error where one of the given addresses was null");
        free_process(user_process, true);
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
        mem_region_t tmp = { .base = fault_addr + 1 };
        reg = sglib_mem_region_t_find_closest_member(as->region_tree, &tmp);
        if (reg != NULL && fault_addr < reg->base + reg->size && fault_addr >= reg->base) {
            // Check permissions for write faults
            if (!debug_is_read_fault() && (reg->perms & REGION_WR) == 0) {
                ZF_LOGE("Trying to write to a read only page");
                free_process(user_process, true);
                return false;
            }
        } else {
            ZF_LOGE("Could not find a valid region for this address: %p", (void*) fault_addr);
            print_regions(user_process_list[badge].addrspace);
            free_process(user_process, true);
            return false;
        }
    }

    /* Try paging in: continue in vm fault if 1 is returned. */
    int try_page_in_res = clock_try_page_in(&user_process, fault_addr);
    if (try_page_in_res < 0) {
        /* Major error */
        free_process(user_process, true);
        return false;
    } else if (!try_page_in_res) {
        /* Success in paging in */
        return true;
    }

    /* Allocate a new frame to be mapped by the shadow page table. */
    frame_ref_t frame_ref = clock_alloc_frame(fault_addr, user_process.pid, 0, 0);
    if (frame_ref == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        free_process(user_process, true);
        return false;
    }

    if (sos_map_frame(&cspace, user_process.vspace, fault_addr, reg->perms, frame_ref, as) != seL4_NoError) {
        ZF_LOGE("Could not map the frame into the two page tables");
        free_process(user_process, true);
        return false;
    }
    
    user_process.size++;
    sync_bin_sem_wait(process_list_sem);
    user_process_list[badge] = user_process;
    sync_bin_sem_post(process_list_sem);
    return true;
}

/**
 * Deals with a syscall and sets the message registers before returning the
 * message info to be passed through to seL4_ReplyRecv()
 */
seL4_MessageInfo_t handle_syscall(seL4_Word badge)
{
    seL4_MessageInfo_t reply_msg;

    /* get the first word of the message, which in the SOS protocol is the number
     * of the SOS "syscall". */
    seL4_Word syscall_number = seL4_GetMR(0);

    /* Process system call */
    switch (syscall_number) {
    case SYSCALL_SOS_OPEN:
        syscall_sos_open(&reply_msg, badge);
        break;
    case SYSCALL_SOS_CLOSE:
        syscall_sos_close(&reply_msg, badge);
        break;
    case SYSCALL_SOS_READ:
        syscall_sos_read(&reply_msg, badge);
        break;
    case SYSCALL_SOS_WRITE:
        syscall_sos_write(&reply_msg, badge);
        break;
    case SYSCALL_SOS_USLEEP:
        /* With clock driver, this system call operation isn't delegated to sos 
           i.e. this function shouldn't ever be called */
        syscall_sos_usleep(&reply_msg, badge);
        break;
    case SYSCALL_SOS_TIME_STAMP:
        /* Same reasoning as the sleep system call for this function too */
        syscall_sos_time_stamp(&reply_msg);
        break;
    case SYSCALL_SYS_BRK:
        syscall_sys_brk(&reply_msg, badge);
        break;
    case SYSCALL_SOS_STAT:
        syscall_sos_stat(&reply_msg, badge);
        break;
    case SYSCALL_SOS_GETDIRENT:
        syscall_sos_getdirent(&reply_msg, badge);
        break;
    case SYSCALL_SYS_MMAP:
        syscall_sys_mmap(&reply_msg, badge);
        break;
    case SYSCALL_SYS_MUNMAP:
        syscall_sys_munmap(&reply_msg, badge);
        break;
    case SYSCALL_PROC_CREATE:
        syscall_proc_create(&reply_msg, badge);
        break;
    case SYSCALL_PROC_DELETE:
        syscall_proc_delete(&reply_msg, badge);
        break;
    case SYSCALL_PROC_GETID:
        syscall_proc_getid(&reply_msg, badge);
        break;
    case SYSCALL_PROC_STATUS:
        syscall_proc_status(&reply_msg, badge);
        break;
    case SYSCALL_PROC_WAIT:
        syscall_proc_wait(&reply_msg, badge);
        break;
    case SYSCALL_SOS_SHARE_VM:
        syscall_sos_share_vm(&reply_msg, badge);
        break;
    default:
        syscall_unknown_syscall(&reply_msg, syscall_number);
    }

    return reply_msg;
}

NORETURN void syscall_loop(void *arg)
{
    pid_t pid = (pid_t)(size_t)arg;
    sync_bin_sem_wait(process_list_sem);
    user_process_t process = user_process_list[pid];
    sync_bin_sem_post(process_list_sem);
    seL4_CPtr reply = process.reply;
    seL4_CPtr ep = process.ep;
    seL4_MessageInfo_t message;
    seL4_Word sender;

    bool have_reply = false;
    seL4_MessageInfo_t reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    while (1) {
        /* Reply (if there is a reply) and block on ep, waiting for an IPC sent over ep */
        if (have_reply) {
            message = seL4_ReplyRecv(ep, reply_msg, &sender, reply);
        } else {
            message = seL4_Recv(ep, &sender, reply);
        }

        /* Wait and post the semaphore if the process id isn't 0 aka the clock driver */
        if (pid) {
            sync_bin_sem_wait(process.handler_busy_sem);
        }
        /* Awake! We got a message - check the label and badge to
         * see what the message is about */
        seL4_Word label = seL4_MessageInfo_get_label(message);
        if (label == seL4_Fault_NullFault) {
            /* It's not a fault or an interrupt, it must be an IPC
             * message from console_test! */
            reply_msg = handle_syscall((seL4_Word) pid);
            have_reply = true;
        } else if (label == seL4_Fault_VMFault) {
            reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);
            have_reply = handle_vm_fault(seL4_GetMR(seL4_VMFault_Addr), (seL4_Word) pid);
        } else {
            /* some kind of fault */
            debug_print_fault(message, APP_NAME);
            /* dump registers too */
            debug_dump_registers(user_process_list[sender].tcb);
            /* Don't reply and recv on nothing */
            have_reply = false;

            ZF_LOGF("The SOS skeleton does not know how to handle faults!");
        }
        if (pid) {
            sync_bin_sem_post(process.handler_busy_sem);
        }
    }
}

NORETURN void irq_loop(void* arg)
{
    seL4_CPtr ntfn = (seL4_CPtr) arg;
    seL4_Word badge = 0;
    while (1) {
        seL4_MessageInfo_t message = seL4_Wait(ntfn, &badge);

        if (badge & IRQ_EP_BADGE) {
            /* It's a notification from our bound notification object! */
            sos_handle_irq_notification(&badge, 0);
        } else {
            /* some kind of fault */
            debug_print_fault(message, APP_NAME);

            ZF_LOGF("The SOS skeleton does not know how to handle faults!");
        }
    }
}

/* Allocate an endpoint and a notification object for sos.
 * Note that these objects will never be freed, so we do not
 * track the allocated ut objects anywhere
 */
static void sos_ipc_init(seL4_CPtr *clock_driver_ep, seL4_CPtr *ntfn)
{
    /* Create an notification object for interrupts */
    ut_t *ut = alloc_retype(ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification object");

    /* Create an endpoint for user application IPC */
    ut = alloc_retype(clock_driver_ep, seL4_EndpointObject, seL4_EndpointBits);
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
    seL4_CPtr ntfn;
    sos_ipc_init(&clock_driver_ep, &ntfn);
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

    init_threads(clock_driver_ep, gdb_recv_ep, sched_ctrl_start, sched_ctrl_end);
#else
    init_threads(clock_driver_ep, clock_driver_ep, sched_ctrl_start, sched_ctrl_end);
#endif /* CONFIG_SOS_GDB_ENABLED */

    frame_table_init(&cspace, seL4_CapInitThreadVSpace);

    /* run sos initialisation tests */
    run_tests(&cspace);

    /* Initialise semaphores for synchronisation */
    init_nfs_sem();
    init_semaphores();
    /* Initialise our swap map and queue for demand paging */
    init_bitmap();
    global_pagetable_create();
    /* Initialise the list of processes and process id bitmap */
    int error = init_proc();
    ZF_LOGF_IF(error, "Failed to initialise process list / bitmap");

    /* Map the timer device (NOTE: this is the same mapping you will use for your timer driver -
     * sos uses the watchdog timers on this page to implement reset infrastructure & network ticks,
     * so touching the watchdog timers here is not recommended!) */
    /* Copy the frame cap allocated for mapping of timer into sos into a new slot for mapping into our driver */
    seL4_CPtr frame = cspace_alloc_slot(&cspace);
    void *timer_vaddr = sos_map_device(&cspace, PAGE_ALIGN_4K(TIMER_MAP_BASE), PAGE_SIZE_4K, frame, true);

    /* Initialise the network hardware. */
    printf("Network init\n");
    network_init(&cspace, timer_vaddr, ntfn, nfs_signal);
    console = network_console_init();
    network_console_register_handler(console, enqueue);
    init_console_sem();

    /* Initialise our swap map and queue for demand paging */
    buffercache_init();
    dentry_init();

#ifdef CONFIG_SOS_GDB_ENABLED
    /* Initialize the debugger */
    seL4_Error err = debugger_init(&cspace, seL4_CapIRQControl, gdb_recv_ep);
    ZF_LOGF_IF(err, "Failed to initialize debugger %d", err);
#endif /* CONFIG_SOS_GDB_ENABLED */

    /* Initialise an irq handling thread. */
    printf("\nSOS entering irq loop\n");
    if (!thread_create(irq_loop, (void *)ntfn, 0, true, seL4_MaxPrio, 0, false, "irq")) {
        ZF_LOGE("Could not create irq handler thread\n");
    }

    /* Initialise the pagefile to write frame data into for demand paging */
    nfs_pagefile = file_create("pagefile", O_RDWR, nfs_pwrite_file, nfs_pread_file);
    io_args args = {.signal_cap = nfs_signal};
    /* Wait for NFS to finish mounting */
    seL4_Wait(nfs_signal, 0);
    error = nfs_open_file(nfs_pagefile, nfs_async_open_cb, &args);
    ZF_LOGF_IF(error, "NFS: Error in opening pagefile");
    nfs_pagefile->handle = args.buff;

    printf("Timer init\n");
    /* Start the clock driver */
    error = start_process(TIMER_DEVICE, true);
    ZF_LOGF_IF(error == -1, "Failed to start clock driver");
    user_process_t clock_driver = user_process_list[error];
    /* Map the timer device to the vspace of the clock driver */
    sos_map_timer(&cspace, clock_driver.vspace, frame, timer_vaddr);
    /* Sets up the timer irqs */
    seL4_CPtr irq_ntfn;
    ut_t *ut = alloc_retype(&irq_ntfn, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(ut == NULL, "Failed to alloc irq ntfn");
    int init_irq_err = init_driver_irq_handling(seL4_CapIRQControl, meson_timeout_irq(MESON_TIMER_A), true, &clock_driver.cspace, irq_ntfn);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to initialise IRQ");
    init_irq_err = init_driver_irq_handling(seL4_CapIRQControl, meson_timeout_irq(MESON_TIMER_B), true, &clock_driver.cspace, irq_ntfn);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to initialise IRQ");
    /* Bind the notification to the clock driver's tcb to get irqs */
    init_irq_err = seL4_TCB_BindNotification(clock_driver.tcb, irq_ntfn);
    ZF_LOGF_IF(init_irq_err != 0, "Failed to bind irq ntfn");
    /* Resume the clock driver process */
    error = seL4_TCB_Resume(clock_driver.tcb);
    ZF_LOGF_IF(error != seL4_NoError, "Failed to resume clock driver");

    /* Start the first user application */
    printf("Start process\n");
    int success = start_process(APP_NAME, false);
    ZF_LOGF_IF(success == -1, "Failed to start process");

    become_hitman();
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

    /* Initialise a semaphore for synchronising accesses to the root cspace. */
    cspace_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!cspace_sem, "No memory for semaphore object");

    ut_t *ut = ut_alloc(seL4_NotificationBits, &cspace);
    if (ut == NULL) {
        ZF_LOGE("No memory for object of size %u", seL4_NotificationBits);
        return -1;
    }
    seL4_CPtr cspace_sem_cptr = cspace_alloc_slot(&cspace);
    if (cspace_sem_cptr == seL4_CapNull) {
        ut_free(ut);
        ZF_LOGE("Failed to allocate slot");
        return -1;
    }

    /* now do the retype */
    seL4_Error err = cspace_untyped_retype(&cspace, ut->cap, cspace_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGE_IFERR(err, "Failed retype untyped");
    if (err != seL4_NoError) {
        ut_free(ut);
        return -1;
    }
    sync_bin_sem_init(cspace_sem, cspace_sem_cptr, 1);

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