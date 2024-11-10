#include "clock_replacement.h"

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

/* The linker will link this symbol to the start address  *
 * of an archive of attached applications.                */
extern char _cpio_archive[];
extern char _cpio_archive_end[];

#define APP_PRIORITY         (0)

struct {
    uint8_t *pid_queue;
    size_t queue_head;
} pid_manager = {.queue_head = 0};

extern seL4_CPtr sched_ctrl_start;
extern seL4_CPtr sched_ctrl_end;
extern seL4_CPtr nfs_signal;
thread_main_f *handler_func = NULL;

user_process_t *user_process_list;

seL4_CPtr proc_signal;

int init_proc()
{
    user_process_list = calloc(NUM_PROC, sizeof(user_process_t));
    if (user_process_list == NULL) {
        return 1;
    }
    pid_manager.pid_queue = calloc(NUM_PROC, sizeof(uint8_t));
    if (pid_manager.pid_queue == NULL) {
        free(user_process_list);
        return 1;
    }
    /* Never freed so we don't keep track */
    ut_t *ut = alloc_retype(&proc_signal, seL4_NotificationObject, seL4_NotificationBits);
    if (proc_signal == seL4_CapNull) {
        ZF_LOGE("No memory for notifications");
        free(pid_manager.pid_queue);
        free(user_process_list);
        return 1;
    }
    /* Put all the possible pids in the queue */
    for (uint8_t i = 0; i < NUM_PROC; i++) {
        pid_manager.pid_queue[i] = i + 1;
    }
    return 0;
}

pid_t get_pid()
{
    size_t head_pos = pid_manager.queue_head;
    do {
        if (pid_manager.pid_queue[pid_manager.queue_head] == (pid_manager.queue_head + 1)) {
            uint8_t pid = pid_manager.pid_queue[pid_manager.queue_head] - 1;
            pid_manager.pid_queue[pid_manager.queue_head] = 0;
            pid_manager.queue_head = (pid_manager.queue_head + 1) % NUM_PROC;
            return ((pid_t) pid);
        }
        if (pid_manager.pid_queue[pid_manager.queue_head] == 0) {
            pid_manager.queue_head = (pid_manager.queue_head + 1) % NUM_PROC;
        }
    } while (head_pos != pid_manager.queue_head);
    return -1;
}

char *get_elf_data(unsigned long *elf_size, char *app_name)
{
    /*io_args args = {.signal_cap = nfs_signal};
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
    uint32_t header_size = header->e_ehsize + (header->e_phentsize * header->e_phnum) + (header->e_shentsize * header->e_shnum);
    data = realloc(data, header_size);
    args.buff = data + (header->e_ehsize + (header->e_phentsize * header->e_phnum));

    error = nfs_pread_file(file, NULL, header->e_shoff, (header->e_shentsize * header->e_shnum), nfs_pagefile_read_cb, &args);
    if (error < (int) (header->e_shentsize * header->e_shnum)) {
        ZF_LOGE("NFS: Error in reading ELF");
        free(data);
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        free(data);
        return NULL;
    }
    return data;*/
    open_file *file = file_create(app_name, O_RDWR, nfs_pwrite_file, nfs_pread_file);
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
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        return NULL;
    }

    Elf64_Ehdr const *header = (void *) data;
    *elf_size = header->e_shoff + (header->e_shentsize * header->e_shnum);
    data = realloc(data, *elf_size);
    args.buff = data;

    error = nfs_pread_file(file, NULL, 0, *elf_size, nfs_pagefile_read_cb, &args);
    if (error < (int) *elf_size) {
        ZF_LOGE("NFS: Error in reading ELF");
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        return NULL;
    }

    error = nfs_close_file(file, nfs_async_close_cb, &args);
    if (error < 0) {
        ZF_LOGE("NFS: Error in closing ELF");
        return NULL;
    }
    file_destroy(file);
    return data;
}

/* helper to conduct freeing operations in the event of an error in a function to prevent memory leaks */
void free_process(user_process_t user_process)
{
    /* Free the file descriptor table */
    if (user_process.fdt != NULL) {
        fdt_destroy(user_process.fdt);
    }
    /* Free all allocated memory for the syscall thread */
    sync_bin_sem_wait(user_process.async_sem); // (for now here) will optimize to delete unnecessary stuff before wait // do for other irqs
    if (user_process.handler_thread != NULL) {
        thread_destroy(user_process.handler_thread);
    }
    /* Free the heap region in the address space */
    remove_region(user_process.addrspace, PROCESS_HEAP_START);
    /* Free the stack region */
    remove_region(user_process.addrspace, PROCESS_STACK_TOP - PAGE_SIZE_4K);
    /* Free the scheduling context and tcb */
    free_untype(&user_process.sched_context, user_process.sched_context_ut);
    free_untype(&user_process.tcb, user_process.tcb_ut);
    /* Delete the ntfn from the user process cspace if in that cspace and free the slot */
    if (!cspace_delete(&user_process.cspace, user_process.ntfn_slot)) {
        cspace_free_slot(&user_process.cspace, user_process.ntfn_slot);
    }
    /* Delete the ep from the user process cspace if in that cspace and free the slot */
    if (!cspace_delete(&user_process.cspace, user_process.ep_slot)) {
        cspace_free_slot(&user_process.cspace, user_process.ep_slot);
    }
    /* Free the ipc buffer region */
    remove_region(user_process.addrspace, PROCESS_IPC_BUFFER);
    /* Free the user process page table and address space */
    if (user_process.addrspace->page_table != NULL) {
        sos_destroy_page_table(user_process.addrspace);
        free_region_tree(user_process.addrspace);
        free(user_process.addrspace);
    }
    /* Destroy the user process cspace */
    if (&user_process.cspace != NULL) {
        cspace_destroy(&user_process.cspace);
    }
    /* Free the user process vspace and ep (vspace unassigned from ASID upon freeing) */
    free_untype(&user_process.vspace, user_process.vspace_ut);
    free_untype(&user_process.ep, user_process.ep_ut);
    free_untype(&user_process.async_cptr, user_process.async_ut);
    free(user_process.async_sem);
    uint8_t id = (uint8_t) user_process.pid;
    user_process_list[(pid_t) id] = (user_process_t){0};
    pid_manager.pid_queue[id] = id + 1;
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
    uintptr_t *sysinfo = (uintptr_t *) elf_getSectionNamed(elf_file, "__vsyscall", NULL);
    if (!sysinfo || !*sysinfo) {
        ZF_LOGE("could not find syscall table for c library");
        return 0;
    }

    /* Map in the stack frame for the user app */
    seL4_Error err = sos_map_frame(cspace, user_process->vspace, stack_bottom, REGION_RD | REGION_WR,
                                   user_process->stack_frame, as);
    if (err != 0) {
        ZF_LOGE("Unable to map stack for user app");
        return 0;
    }
    user_process->size++;

    /* allocate a slot to duplicate the stack frame cap so we can map it into our address space */
    seL4_CPtr local_stack_cptr = cspace_alloc_slot(cspace);
    if (local_stack_cptr == seL4_CapNull) {
        ZF_LOGE("Failed to alloc slot for stack");
        return 0;
    }

    /* copy the stack frame cap into the slot */
    err = cspace_copy(cspace, local_stack_cptr, cspace, user_process->stack, seL4_AllRights);
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
        frame_ref_t frame = clock_alloc_frame(as, stack_bottom);
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return 0;
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
    user_process_t user_process;
    user_process.pid = get_pid();
    if (user_process.pid == -1) {
        ZF_LOGE("Ran out of IDs for processes");
        return -1;
    }
    user_process.app_name = app_name;
    user_process.size = 0;
    user_process.parent_pid = 0;

    if (func != NULL) {
        handler_func = func;
    }

    user_process.async_sem = malloc(sizeof(sync_bin_sem_t));
    if (user_process.async_sem == NULL) {
        ZF_LOGE("No memory for new semaphore object");
        free_process(user_process);
        return -1;
    }
    user_process.async_ut = alloc_retype(&user_process.async_cptr, seL4_NotificationObject, seL4_NotificationBits);
    if (user_process.async_cptr == seL4_CapNull) {
        ZF_LOGE("No memory for new notification object");
        free_process(user_process);
        return -1;
    }
    sync_bin_sem_init(user_process.async_sem, user_process.async_cptr, 1);

    user_process.ep_ut = alloc_retype(&user_process.ep, seL4_EndpointObject, seL4_EndpointBits);
    if (user_process.ep == seL4_CapNull) {
        ZF_LOGE("No memory for endpoints");
        free_process(user_process);
        return -1;
    }

    /* Create a VSpace */
    user_process.vspace_ut = alloc_retype(&user_process.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (user_process.vspace_ut == NULL) {
        ZF_LOGE("Failed to create vspace");
        free_process(user_process);
        return -1;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, user_process.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        free_process(user_process);
        return -1;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &user_process.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        free_process(user_process);
        return -1;
    }

    /* Initialise the process address space */
    user_process.addrspace = as_create();
    if (user_process.addrspace == NULL) {
        ZF_LOGE("Failed to create address space");
        free_process(user_process);
        return -1;
    }

    mem_region_t *region = as_define_ipc_buff(user_process.addrspace);
    if (region == NULL) {
        ZF_LOGE("Failed to create ipc buffer region");
        free_process(user_process);
        return -1;
    }

    /* Create an IPC buffer */
    user_process.ipc_buffer_frame = clock_alloc_frame(user_process.addrspace, PROCESS_IPC_BUFFER);
    if (user_process.ipc_buffer_frame == NULL_FRAME) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        free_process(user_process);
        return -1;
    }
    user_process.ipc_buffer = frame_page(user_process.ipc_buffer_frame);

    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    user_process.ep_slot = cspace_alloc_slot(&user_process.cspace);
    if (user_process.ep_slot == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        free_process(user_process);
        return -1;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&user_process.cspace, user_process.ep_slot, &cspace, user_process.ep, seL4_AllRights, (seL4_Word) user_process.pid);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        free_process(user_process);
        return -1;
    }

    user_process.ntfn_slot = cspace_alloc_slot(&user_process.cspace);
    if (user_process.ntfn_slot == seL4_CapNull) {
        ZF_LOGE("Failed to alloc ntfn slot");
        free_process(user_process);
        return -1;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&user_process.cspace, user_process.ntfn_slot, &cspace, proc_signal, seL4_AllRights, (seL4_Word) user_process.pid);
    if (err) {
        ZF_LOGE("Failed to mint ntfn");
        free_process(user_process);
        return -1;
    }

    /* Create a new TCB object */
    user_process.tcb_ut = alloc_retype(&user_process.tcb, seL4_TCBObject, seL4_TCBBits);
    if (user_process.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        free_process(user_process);
        return -1;
    }
    
    /* Configure the TCB */
    err = seL4_TCB_Configure(user_process.tcb,
                             user_process.cspace.root_cnode, seL4_NilData,
                             user_process.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             user_process.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        free_process(user_process);
        return -1;
    }
    
    /* Create scheduling context */
    user_process.sched_context_ut = alloc_retype(&user_process.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (user_process.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        free_process(user_process);
        return -1;
    }
    
    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, user_process.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        free_process(user_process);
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
        free_process(user_process);
        return -1;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(user_process.tcb, app_name);

    /* Read the ELF header from NFS */
    ZF_LOGI("\nStarting \"%s\"...\n", app_name);
    unsigned long elf_size;
    elf_t elf_file = {};
    size_t cpio_len = _cpio_archive_end - _cpio_archive;
    const char *elf_base = cpio_get_file(_cpio_archive, cpio_len, app_name, &elf_size);
    //open_file *elf = file_create(app_name, O_RDWR, nfs_pwrite_file, nfs_pread_file);
    //char *elf_base = get_elf_data(&elf_size, elf);
    //char *elf_base = get_elf_data(&elf_size, app_name);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to open or read %s from NFS", app_name);
        free_process(user_process);
        return -1;
    }

    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        free_process(user_process);
        return -1;
    }

    /* set up the stack */
    seL4_Word sp = init_process_stack(&user_process, &cspace, seL4_CapInitThreadVSpace, &elf_file);
    if ((int) sp == -1) {
        ZF_LOGE("Failed to set up the stack");
        free_process(user_process);
        return -1;
    }

    /* Allocating a region for the heap */
    user_process.addrspace->heap_reg = as_define_heap(user_process.addrspace);
    if (user_process.addrspace->heap_reg == NULL) {
        ZF_LOGE("Failed to create the heap region");
        free_process(user_process);
        return -1;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, user_process.vspace, PROCESS_IPC_BUFFER, REGION_RD | REGION_WR,
                        user_process.ipc_buffer_frame, user_process.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        free_process(user_process);
        return -1;
    }
    user_process.size++;

    /* load the elf image from nfs */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace, &user_process.size);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        free_process(user_process);
        return -1;
    }

    init_threads(user_process.ep, user_process.ep, sched_ctrl_start, sched_ctrl_end);

    user_process.handler_thread = thread_create(handler_func, (void *) user_process.ep, user_process.pid, true, seL4_MaxPrio, seL4_CapNull, true);
    if (user_process.handler_thread == NULL) {
        ZF_LOGE("Could not create system call handler thread for %s\n", app_name);
        free_process(user_process);
        return -1;
    }

    /* Initialise the per-process file descriptor table */
    char error;
    user_process.fdt = fdt_create(&error);
    if (error) {
        ZF_LOGE("Failed to initialise the file descriptor table");
        free_process(user_process);
        return -1;
    }

    open_file *file = file_create("console", O_WRONLY, netcon_send, deque);
    uint32_t fd;
    err = fdt_put(user_process.fdt, file, &fd); // initialise stdout
    if (err) {
        ZF_LOGE("Failed to initialise stdout");
        free_process(user_process);
        return -1;
    }
    err = fdt_put(user_process.fdt, file, &fd); // initialise stderr
    if (err) {
        ZF_LOGE("Failed to initialise stderr");
        free_process(user_process);
        return -1;
    }
    //err = fdt_put(user_process.fdt, elf, &fd);
    //if (err) {
    //    ZF_LOGE("Failed to store elf file");
    //    free_process(user_process);
    //    return -1;
    //}

    /* Start the new process */
    seL4_UserContext context = {
        .pc = elf_getEntryPoint(&elf_file),
        .sp = sp,
    };
    printf("Starting ttytest at %p\n", (void *) context.pc);
    err = seL4_TCB_WriteRegisters(user_process.tcb, 1, 0, 2, &context);
    if (err) {
        ZF_LOGE("Failed to write registers");
        free_process(user_process);
        return -1;
    }

    //free(elf_file.elfFile);
    user_process.stime = timestamp_ms(timestamp_get_freq());
    user_process_list[user_process.pid] = user_process;
    return user_process.pid;
}

void syscall_proc_create(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_CREATE);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

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
    user_process_list[pid].parent_pid = badge;
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
    user_process_t user_process = user_process_list[pid];
    if (user_process.stime == 0 || badge == (seL4_Word) pid) {
        seL4_SetMR(0, -1);
        return;
    }
    for (int i = 0; i < NUM_PROC; i++) {
        seL4_Signal(proc_signal); // maybe have after freeing // find better way
    }
    free_process(user_process);
    seL4_SetMR(0, 0);
}

void syscall_proc_getid(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_GETID);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, user_process_list[badge].pid);
}

void syscall_proc_status(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_STATUS);
    ZF_LOGE("WHERE DID I DIE");
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    ZF_LOGE("WHERE DID I DIE");
    user_process_t user_process = user_process_list[badge];
    ZF_LOGE("WHERE DID I DIE");
    seL4_Word vaddr = seL4_GetMR(1);
    ZF_LOGE("WHERE DID I DIE");
    unsigned max = seL4_GetMR(2);
    ZF_LOGE("WHERE DID I DIE");

    unsigned num_proc = 0;
    ZF_LOGE("WHERE DID I DIE");
    for (int i = 0; i < NUM_PROC; i++) {
        ZF_LOGE("WHERE DID I DIE");
        if (user_process_list[i].stime == 0) {
            ZF_LOGE("WHERE DID I DIE");
            continue;
        }
        ZF_LOGE("WHERE DID I DIE");
        user_process_t process = user_process_list[i];
        ZF_LOGE("WHERE DID I DIE");
        sos_process_t pinfo = {.pid = process.pid, .size = process.size, .stime = process.stime};
        ZF_LOGE("WHERE DID I DIE");
        for (size_t i = 0; i < strlen(process.app_name); i++) {
            ZF_LOGE("WHERE DID I DIE");
            pinfo.command[i] = process.app_name[i];
            ZF_LOGE("WHERE DID I DIE");
        }
        ZF_LOGE("WHERE DID I DIE");
        int res = perform_cpy(user_process, sizeof(sos_process_t), vaddr, false, &pinfo);
        ZF_LOGE("WHERE DID I DIE");
        if (res < (int) sizeof(sos_process_t)) {
            ZF_LOGE("WHERE DID I DIE");
            seL4_SetMR(0, -1);
            return;
        }
        ZF_LOGE("WHERE DID I DIE");
        num_proc++;
        ZF_LOGE("WHERE DID I DIE");
        vaddr += res;
        ZF_LOGE("WHERE DID I DIE");
        if (num_proc >= max) {
            ZF_LOGE("WHERE DID I DIE");
            break;
        }
        ZF_LOGE("WHERE DID I DIE");
    }
    ZF_LOGE("WHERE DID I DIE");
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

    while (1) {
        seL4_Word sender = 0;
        if (pid >= 0 && user_process_list[pid].stime == 0) {
            seL4_SetMR(0, pid);
            return;
        }
        seL4_Wait(proc_signal, &sender);
        if (pid == -1 || sender == (seL4_Word) pid) {
            seL4_SetMR(0, sender);
            return;
        }
    }
}