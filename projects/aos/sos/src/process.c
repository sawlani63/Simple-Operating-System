#include "clock_replacement.h"

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

#define APP_PRIORITY         (0)

extern seL4_CPtr sched_ctrl_start;
extern seL4_CPtr sched_ctrl_end;
extern seL4_CPtr nfs_signal;
extern bool console_open_for_read;
extern sync_bin_sem_t *file_sem;
thread_main_f *handler_func = NULL;

seL4_CPtr proc_signal; // for waiting on pid -1
user_process_t *user_process_list;
pid_t *pid_queue;
int pid_queue_head = 0;
int pid_queue_tail = NUM_PROC - 1;

sync_bin_sem_t *pid_queue_sem = NULL;
sync_bin_sem_t *process_list_sem = NULL;

int init_proc()
{
    user_process_list = calloc(NUM_PROC, sizeof(user_process_t));
    if (user_process_list == NULL) {
        return 1;
    }
    pid_queue = malloc(NUM_PROC * sizeof(pid_t));
    if (pid_queue == NULL) {
        free(user_process_list);
        return 1;
    }
    /* Never freed so we don't keep track */
    ut_t *ut = alloc_retype(&proc_signal, seL4_EndpointObject, seL4_EndpointBits);
    if (proc_signal == seL4_CapNull || ut == NULL) {
        ZF_LOGE("No memory for notifications");
        free(pid_queue);
        free(user_process_list);
        return 1;
    }
    /* Put all the possible pids in the queue */
    for (int i = 0; i < NUM_PROC; i++) {
        pid_queue[i] = i;
    }

    pid_queue_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!pid_queue_sem, "No memory for new semaphore object");
    seL4_CPtr pid_manager_cptr;
    ut = alloc_retype(&pid_manager_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_bin_sem_init(pid_queue_sem, pid_manager_cptr, 1);

    process_list_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!process_list_sem, "No memory for new semaphore object");
    seL4_CPtr process_list_cptr;
    ut = alloc_retype(&process_list_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_bin_sem_init(process_list_sem, process_list_cptr, 1);
    return 0;
}

static pid_t get_pid() {
    sync_bin_sem_wait(pid_queue_sem);

    if (pid_queue_head == pid_queue_tail) {
        sync_bin_sem_post(pid_queue_sem);
        return -1;
    }

    pid_t pid = pid_queue[pid_queue_head];
    pid_queue_head = (pid_queue_head + 1) % NUM_PROC;

    sync_bin_sem_post(pid_queue_sem);
    return pid;
}

static void free_pid(pid_t pid) {
    sync_bin_sem_wait(pid_queue_sem);

    if ((pid_queue_tail + 1) % NUM_PROC == pid_queue_head) {
        sync_bin_sem_post(pid_queue_sem);
        return;
    }

    pid_queue[pid_queue_tail] = pid;
    pid_queue_tail = (pid_queue_tail + 1) % NUM_PROC;

    sync_bin_sem_post(pid_queue_sem);
}

char *get_elf_header(open_file *file, unsigned long *elf_size)
{
    io_args args = {.signal_cap = nfs_signal};
    int error = nfs_open_file(file, nfs_async_open_cb, &args);
    if (error) {
        ZF_LOGE("NFS: Error in opening app");
        return NULL;
    }
    file->handle = args.buff;

    char *data = malloc(sizeof(char) * PAGE_SIZE_4K);
    args.buff = data;
    error = nfs_pread_file(file, NULL, 0, PAGE_SIZE_4K, nfs_pagefile_read_cb, &args);
    if (error < (int) PAGE_SIZE_4K) {
        ZF_LOGE("NFS: Error in reading ELF and program headers");
        free(data);
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        free(data);
        return NULL;
    }

    Elf64_Ehdr const *header = (void *) data;
    *elf_size = header->e_shoff + (header->e_shentsize * header->e_shnum);
    return data;
}

extern bool console_open_for_read;
extern sync_bin_sem_t *file_sem;
/* helper to conduct freeing operations in the event of an error in a function to prevent memory leaks */
void free_process(user_process_t user_process, bool suicidal)
{
    /**
     * At this stage there can be two types of threads that call free_process.
     * 1. A thread trying to kill a separate thread.
     * 2. A thread trying to kill itself (a suicidal thread).
     * We need to be particularly careful with suicidal threads as we MUST deallocate their handler last.
     */

    /* Free the scheduling context and tcb for the user process. We will do this first to halt the process. */
    free_untype(&user_process.sched_context, user_process.sched_context_ut);
    free_untype(&user_process.tcb, user_process.tcb_ut);

    /* Wait for outstanding I/O to finish before starting to free the rest of the process. */
    if (user_process.async_sem != NULL) {
        sync_bin_sem_wait(user_process.async_sem);
        free_untype(&user_process.async_cptr, user_process.async_ut);
        free(user_process.async_sem);
    }

    /* Free the file descriptor table. */
    if (user_process.fdt != NULL) {
        if (user_process.fdt->files[0] != NULL) {
            /* Relinquish control over stdin if I ever had it in the first place. */
            sync_bin_sem_wait(file_sem);
            console_open_for_read = false;
            sync_bin_sem_post(file_sem);
        }
        fdt_destroy(user_process.fdt);
    }

    /* Destroy EVERY region and page including the intermediate structures in the region rb-tree and shadow page table. */
    if (user_process.addrspace->page_table != NULL) {
        sos_destroy_page_table(user_process.addrspace);
        free_region_tree(user_process.addrspace);
        free(user_process.addrspace);
    }

    /* Destroy the user process cspace. This destroys all the caps inside of this cspace as well. */
    if (&user_process.cspace != NULL) {
        cspace_destroy(&user_process.cspace);
    }

    /* Signal all the other processes waiting on the process that is marked as deleted. */
    for (int i = 0; i < NUM_PROC; i++) {
        seL4_Signal(user_process.wake);
        seL4_SetMR(0, (seL4_Word) user_process.pid);
        seL4_NBSend(proc_signal, seL4_MessageInfo_new(0, 0, 0, 1));
    }

    /* Mark the pid as free in the pid_queue, and zero out the entry in the user process list. */
    sync_bin_sem_wait(process_list_sem);
    user_process_list[user_process.pid] = (user_process_t){0};
    sync_bin_sem_post(process_list_sem);
    free_pid(user_process.pid);

    /* Free the remainder of the untyped memory and caps for the process, including the VSpace and other ntfn/ep objects. */
    free_untype(&user_process.wake, user_process.wake_ut);
    free_untype(&user_process.reply, user_process.reply_ut);
    free_untype(&user_process.ep, user_process.ep_ut);
    free_untype(&user_process.vspace, user_process.vspace_ut);

    /* Finally, destroy the process's handling thread. Always doing this last makes it safe to call for suicidal threads. */
    if (user_process.handler_thread != NULL) {
        if (!suicidal) {
            sync_bin_sem_wait(user_process.handler_busy_sem);
        }
        free_untype(&user_process.handler_busy_cptr, user_process.handler_busy_ut);
        free(user_process.handler_busy_sem);
        request_destroy(user_process.handler_thread);
    }
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
static uintptr_t init_process_stack(user_process_t *user_process, cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file)
{
    addrspace_t *as = user_process->addrspace;
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
    user_process->stack_frame = clock_alloc_frame(as, stack_bottom);
    if (user_process->stack_frame == NULL_FRAME) {
        ZF_LOGD("Failed to alloc frame");
        return -1;
    }
    user_process->stack = frame_page(user_process->stack_frame);

    /* find the vsyscall table */
    /*uintptr_t *sysinfo = (uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL);
    if (!sysinfo || !*sysinfo) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }*/

    /* Map in the stack frame for the user app */
    seL4_Error err = sos_map_frame(cspace, user_process->vspace, stack_bottom, REGION_RD | REGION_WR,
                                   user_process->stack_frame, as);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return -1;
    }
    user_process->size++;

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return -1;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, user_process->stack, seL4_AllRights);
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

    //index = stack_write(local_stack_top, index, *sysinfo);
    //index = stack_write(local_stack_top, index, AT_SYSINFO);

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
        frame_ref_t frame = clock_alloc_frame(as, stack_bottom);
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return -1;
        }

        err = sos_map_frame(cspace, user_process->vspace, stack_bottom,
                            REGION_RD | REGION_WR, frame, as);
        user_process->size++;
    }

    return stack_top;
}

/* Start the first process, and return true if successful
 *
 * This function will leak memory if the process does not start successfully.
 * TODO: avoid leaking memory once you implement real processes, otherwise a user
 *       can force your OS to run out of memory by creating lots of failed processes.
 */
int start_process(char *app_name, thread_main_f *func)
{
    user_process_t user_process = (user_process_t) {0};
    user_process.pid = get_pid();
    if (user_process.pid == -1) {
        ZF_LOGE("Ran out of IDs for processes");
        return -1;
    }
    user_process.app_name = app_name;

    if (func != NULL) {
        handler_func = func;
    }

    user_process.async_sem = malloc(sizeof(sync_bin_sem_t));
    if (user_process.async_sem == NULL) {
        ZF_LOGE("No memory for new semaphore object");
        free_process(user_process, false);
        return -1;
    }
    user_process.async_ut = alloc_retype(&user_process.async_cptr, seL4_NotificationObject, seL4_NotificationBits);
    if (user_process.async_cptr == seL4_CapNull) {
        ZF_LOGE("No memory for new notification object");
        free_process(user_process, false);
        return -1;
    }
    sync_bin_sem_init(user_process.async_sem, user_process.async_cptr, 1);

    user_process.handler_busy_sem = malloc(sizeof(sync_bin_sem_t));
    if (user_process.handler_busy_sem == NULL) {
        ZF_LOGE("No memory for new semaphore object");
        free_process(user_process, false);
        return -1;
    }
    user_process.handler_busy_ut = alloc_retype(&user_process.handler_busy_cptr, seL4_NotificationObject, seL4_NotificationBits);
    if (user_process.handler_busy_cptr == seL4_CapNull) {
        ZF_LOGE("No memory for new notification object");
        free_process(user_process, false);
        return -1;
    }
    sync_bin_sem_init(user_process.handler_busy_sem, user_process.handler_busy_cptr, 1);

    user_process.ep_ut = alloc_retype(&user_process.ep, seL4_EndpointObject, seL4_EndpointBits);
    if (user_process.ep == seL4_CapNull) {
        ZF_LOGE("No memory for endpoints");
        free_process(user_process, false);
        return -1;
    }

    /* Create a VSpace */
    user_process.vspace_ut = alloc_retype(&user_process.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (user_process.vspace_ut == NULL) {
        ZF_LOGE("Failed to create vspace");
        free_process(user_process, false);
        return -1;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, user_process.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        free_process(user_process, false);
        return -1;
    }

    user_process.reply_ut = alloc_retype(&user_process.reply, seL4_ReplyObject, seL4_ReplyBits);
    if (user_process.reply_ut == NULL) {
        ZF_LOGE("Failed to create reply object");
        free_process(user_process, false);
        return -1;
    }

    user_process.wake_ut = alloc_retype(&user_process.wake, seL4_NotificationObject, seL4_NotificationBits);
    if (user_process.wake_ut == NULL) {
        ZF_LOGE("Failed to create notification object");
        free_process(user_process, false);
        return -1;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &user_process.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        free_process(user_process, false);
        return -1;
    }

    /* Initialise the process address space */
    user_process.addrspace = as_create();
    if (user_process.addrspace == NULL) {
        ZF_LOGE("Failed to create address space");
        free_process(user_process, false);
        return -1;
    }

    mem_region_t *region = as_define_ipc_buff(user_process.addrspace);
    if (region == NULL) {
        ZF_LOGE("Failed to create ipc buffer region");
        free_process(user_process, false);
        return -1;
    }

    /* Create an IPC buffer */
    user_process.ipc_buffer_frame = clock_alloc_frame(user_process.addrspace, PROCESS_IPC_BUFFER);
    if (user_process.ipc_buffer_frame == NULL_FRAME) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        free_process(user_process, false);
        return -1;
    }
    user_process.ipc_buffer = frame_page(user_process.ipc_buffer_frame);

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    user_process.ep_slot = cspace_alloc_slot(&user_process.cspace);
    if (user_process.ep_slot == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        free_process(user_process, false);
        return -1;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&user_process.cspace, user_process.ep_slot, &cspace, user_process.ep, seL4_AllRights, (seL4_Word) user_process.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        free_process(user_process, false);
        return -1;
    }

    /* Create a new TCB object */
    user_process.tcb_ut = alloc_retype(&user_process.tcb, seL4_TCBObject, seL4_TCBBits);
    if (user_process.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        free_process(user_process, false);
        return -1;
    }
    
    /* Configure the TCB */
    err = seL4_TCB_Configure(user_process.tcb,
                             user_process.cspace.root_cnode, seL4_NilData,
                             user_process.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             user_process.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        free_process(user_process, false);
        return -1;
    }
    
    /* Create scheduling context */
    user_process.sched_context_ut = alloc_retype(&user_process.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (user_process.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        free_process(user_process, false);
        return -1;
    }
    
    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, user_process.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        free_process(user_process, false);
        return -1;
    }
    
    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(user_process.tcb, seL4_CapInitThreadTCB, seL4_MinPrio, APP_PRIORITY,
                                  user_process.sched_context, user_process.ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        free_process(user_process, false);
        return -1;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(user_process.tcb, app_name);

    /* Read the ELF header from NFS */
    ZF_LOGI("\nStarting \"%s\"...\n", app_name);
    unsigned long elf_size;
    elf_t elf_file = {};
    open_file *elf = file_create(app_name, O_RDWR, nfs_pwrite_file, nfs_pread_file);
    char *elf_base = get_elf_header(elf, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to open or read %s from NFS", app_name);
        free_process(user_process, false);
        return -1;
    }

    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        free_process(user_process, false);
        return -1;
    }

    /* set up the stack */
    seL4_Word sp = init_process_stack(&user_process, &cspace, seL4_CapInitThreadVSpace, &elf_file);
    if ((int) sp == -1) {
        ZF_LOGE("Failed to set up the stack");
        free_process(user_process, false);
        return -1;
    }

    /* Allocating a region for the heap */
    user_process.addrspace->heap_reg = as_define_heap(user_process.addrspace);
    if (user_process.addrspace->heap_reg == NULL) {
        ZF_LOGE("Failed to create the heap region");
        free_process(user_process, false);
        return -1;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, user_process.vspace, PROCESS_IPC_BUFFER, REGION_RD | REGION_WR,
                        user_process.ipc_buffer_frame, user_process.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        free_process(user_process, false);
        return -1;
    }
    user_process.size++;

    /* load the elf image from nfs */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace, &user_process.size, elf);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        free_process(user_process, false);
        return -1;
    }
    file_destroy(elf);

    init_threads(user_process.ep, user_process.ep, sched_ctrl_start, sched_ctrl_end);

    if (func == NULL) { // find better way
        user_process.handler_thread = thread_create(handler_func, (void *) user_process.pid, user_process.pid, true, seL4_MaxPrio, seL4_CapNull, true);
        if (user_process.handler_thread == NULL) {
            ZF_LOGE("Could not create system call handler thread for %s\n", app_name);
            free_process(user_process, false);
            return -1;
        }
    }

    /* Initialise the per-process file descriptor table */
    char error;
    user_process.fdt = fdt_create(&error);
    if (error) {
        ZF_LOGE("Failed to initialise the file descriptor table");
        free_process(user_process, false);
        return -1;
    }

    open_file *file = file_create("console", O_WRONLY, netcon_send, deque);
    uint32_t fd;
    err = fdt_put(user_process.fdt, file, &fd); // initialise stdout
    if (err) {
        ZF_LOGE("Failed to initialise stdout");
        free_process(user_process, false);
        return -1;
    }
    err = fdt_put(user_process.fdt, file, &fd); // initialise stderr
    if (err) {
        ZF_LOGE("Failed to initialise stderr");
        free_process(user_process, false);
        return -1;
    }

    /* Start the new process */
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };
    printf("Starting ttytest at %p\n", (void *) context.pc);
    err = seL4_TCB_WriteRegisters(user_process.tcb, 1, 0, 2, &context);
    if (err) {
        ZF_LOGE("Failed to write registers");
        free_process(user_process, false);
        return -1;
    }

    free(elf_file.elfFile);
    user_process.stime = timestamp_ms(timestamp_get_freq());
    user_process_list[user_process.pid] = user_process;
    return user_process.pid;
}

void syscall_proc_create(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_CREATE);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    seL4_Word vaddr = seL4_GetMR(1);
    int len = seL4_GetMR(2) + 1;

    char *path = malloc(len);
    int res = perform_cpy(user_process, len, vaddr, true, path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }
    path[len - 1] = '\0';

    pid_t pid = start_process(path, NULL);
    seL4_SetMR(0, pid);
}

void syscall_proc_delete(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_DELETE);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    pid_t pid = seL4_GetMR(1);
    if (pid < 0 || pid >= NUM_PROC) {
        seL4_SetMR(0, -1);
        return;
    }
    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[pid];
    sync_bin_sem_post(process_list_sem);
    if (user_process.stime == 0) {
        seL4_SetMR(0, -1);
        return;
    }
    if (badge == (seL4_Word) pid) {
        free_process(user_process, true);
    } else {
        free_process(user_process, false);
    }
    seL4_SetMR(0, 0);
}

void syscall_proc_getid(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_GETID);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    sync_bin_sem_wait(process_list_sem);
    pid_t pid = user_process_list[badge].pid;
    sync_bin_sem_post(process_list_sem);
    seL4_SetMR(0, pid);
}

void syscall_proc_status(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_STATUS);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word vaddr = seL4_GetMR(1);
    unsigned max = seL4_GetMR(2);
    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    unsigned num_proc = 0;
    for (int i = 0; i < NUM_PROC; i++) {
        sync_bin_sem_wait(process_list_sem);
        if (user_process_list[i].stime == 0) {
            sync_bin_sem_post(process_list_sem);
            continue;
        }
        user_process_t process = user_process_list[i];
        sync_bin_sem_post(process_list_sem);
        sos_process_t pinfo = {.pid = process.pid, .size = process.size, .stime = process.stime};
        for (size_t i = 0; i < strlen(process.app_name); i++) {
            pinfo.command[i] = process.app_name[i];
        }
        int res = perform_cpy(user_process, sizeof(sos_process_t), vaddr, false, &pinfo);
        if (res < (int) sizeof(sos_process_t)) {
            seL4_SetMR(0, -1);
            return;
        }
        num_proc++;
        vaddr += res;
        if (num_proc >= max) {
            break;
        }
    }
    seL4_SetMR(0, num_proc);
}

void syscall_proc_wait(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_STATUS);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    pid_t pid = seL4_GetMR(1);
    if (pid < -1 || pid >= NUM_PROC || badge == (seL4_Word) pid) {
        seL4_SetMR(0, -1);
        return;
    }

    sync_bin_sem_wait(process_list_sem);
    user_process_t my_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    if (pid >= 0) {
        sync_bin_sem_wait(process_list_sem);
        user_process_t user_process = user_process_list[pid];
        sync_bin_sem_post(process_list_sem);
        sync_bin_sem_post(my_process.handler_busy_sem);
        seL4_Wait(user_process.wake, 0);
        sync_bin_sem_wait(my_process.handler_busy_sem);
        seL4_SetMR(0, pid);
    } else {
        seL4_CPtr reply;
        ut_t *ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
        if (ut == NULL) {
            seL4_SetMR(0, -1);
            return;
        }
        seL4_Recv(proc_signal, 0, reply);
        free_untype(&reply, ut);
        seL4_SetMR(0, seL4_GetMR(0));
    }
}

sos_thread_t *get_thread(pid_t id) {
    user_process_t user_process = user_process_list[id];
    return user_process.handler_thread;
}