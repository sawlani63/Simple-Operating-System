#include "clock_replacement.h"

/* The number of additional stack pages to provide to the initial
 * process */
#define INITIAL_PROCESS_EXTRA_STACK_PAGES 4

#define APP_PRIORITY         (0)
#define APP_EP_BADGE         (101)

extern seL4_CPtr sched_ctrl_start;
extern seL4_CPtr sched_ctrl_end;
extern seL4_CPtr nfs_signal;
thread_main_f *handler_func = NULL;

user_process_t *user_process_list;
uint8_t *pid_map;

int init_proc_obj()
{
    user_process_list = calloc(NUM_PROC, sizeof(user_process_t));
    if (user_process_list == NULL) {
        return 1;
    }
    pid_map = calloc(NUM_PROC, sizeof(uint8_t));
    if (pid_map == NULL) {
        free(user_process_list);
        return 1;
    }
    return 0;
}

void mark_pid_used(uint32_t block_num) {
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    pid_map[index] |= (1 << bit_index);
}

void mark_pid_free(uint32_t block_num) {
    uint32_t index = block_num / 8;
    uint8_t bit_index = block_num % 8;
    pid_map[index] &= ~(1 << bit_index);
}

/* Find first free block (returns block number, or -1 if none found) */
int find_first_free_block() {
    for (uint32_t index = 0; index < NUM_PROC; index++) {
        // If not all blocks in this byte are used
        if (pid_map[index] != 0xFF) {
            for (uint8_t bit_index = 0; bit_index < 8; bit_index++) {
                if (!(pid_map[index] & (1 << bit_index))) {
                    mark_pid_used((index * 8) + bit_index);
                    return (index * 8) + bit_index;
                }
            }
        }
    }
    return -1;
}

char *get_elf_data(char *app_name, unsigned long *elf_size)
{
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

    // close file in fdt and nfs
    return data;
}

/* helper to conduct freeing operations in the event of an error in a function to prevent memory leaks */
void free_mem(user_process_t user_process, seL4_CPtr user_ep, mem_region_t *region, seL4_CPtr ep, ut_t *ut)
{
    // free elf
    // free handler thread
    /* Free the heap region in the address space */
    if (user_process.addrspace != NULL && user_process.addrspace->heap_reg != NULL) {
        free(user_process.addrspace->heap_reg);
    }
    // free stack
    /* Free the scheduling context and tcb */
    free_untype(&user_process.sched_context, user_process.sched_context_ut);
    free_untype(&user_process.tcb, user_process.tcb_ut);
    /* Delete the user_ep from the user process cspace if in that cspace */
    if (!cspace_delete(&user_process.cspace, user_ep)) {
        cspace_free_slot(&user_process.cspace, user_ep);   
    }
    /* Free the user_ep, ipc buffer frame, cptr and region */
    free_untype(&user_ep, NULL);
    free_frame(user_process.ipc_buffer_frame);
    free_untype(&user_process.ipc_buffer, NULL);
    if (region != NULL) {
        free(region);
    }
    /* Free the user process page table and address space */
    if (user_process.addrspace->page_table != NULL) {
        free(user_process.addrspace->page_table);
        free(user_process.addrspace);
    }
    /* Destroy the user process cspace */
    if (&user_process.cspace != NULL) {
        cspace_destroy(&user_process.cspace);
    }
    // unassign vspace from ASID
    /* Free the user process vspace and ep */
    free_untype(&user_process.vspace, user_process.vspace_ut);
    free_untype(&ep, ut);
}

static int stack_write(seL4_Word *mapped_stack, int index, uintptr_t val)
{
    mapped_stack[index] = val;
    return index - 1;
}

/* set up System V ABI compliant stack, so that the process can
 * start up and initialise the C library */
static uintptr_t init_process_stack(user_process_t user_process, cspace_t *cspace, seL4_CPtr local_vspace, elf_t *elf_file)
{
    addrspace_t *as = user_process.addrspace;
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
    user_process.stack_frame = clock_alloc_frame(as, stack_bottom);
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
                                   user_process.stack_frame, as);
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
        frame_ref_t frame = clock_alloc_frame(as, stack_bottom);
        if (frame == NULL_FRAME) {
            ZF_LOGE("Couldn't allocate additional stack frame");
            return 0;
        }

        err = sos_map_frame(cspace, user_process.vspace, stack_bottom,
                            REGION_RD | REGION_WR, frame, as);
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
    user_process.pid = find_first_free_block();
    if (user_process.pid == -1) {
        ZF_LOGE("Ran out of IDs for processes");
        return -1;
    }

    if (func != NULL) {
        handler_func = func;
    }
    // replace ep with ipc_ep and try
    seL4_CPtr ep;
    ut_t *ut = alloc_retype(&ep, seL4_EndpointObject, seL4_EndpointBits);
    if (!ut) {
        ZF_LOGF_IF(!ut, "No memory for endpoint");
        return -1;
    }

    /* Create a VSpace */
    user_process.vspace_ut = alloc_retype(&user_process.vspace, seL4_ARM_PageGlobalDirectoryObject,
                                              seL4_PGDBits);
    if (user_process.vspace_ut == NULL) {
        ZF_LOGE("Failed to create vspace");
        free_mem(user_process, seL4_CapNull, NULL, ep, ut);
        return -1;
    }

    /* assign the vspace to an asid pool */
    seL4_Word err = seL4_ARM_ASIDPool_Assign(seL4_CapInitThreadASIDPool, user_process.vspace);
    if (err != seL4_NoError) {
        ZF_LOGE("Failed to assign asid pool");
        free_mem(user_process, seL4_CapNull, NULL, ep, ut);
        return -1;
    }

    /* Create a simple 1 level CSpace */
    err = cspace_create_one_level(&cspace, &user_process.cspace);
    if (err != CSPACE_NOERROR) {
        ZF_LOGE("Failed to create cspace");
        free_mem(user_process, seL4_CapNull, NULL, ep, ut);
        return -1;
    }

    /* Initialise the process address space */
    user_process.addrspace = as_create();
    if (user_process.addrspace == NULL) {
        ZF_LOGE("Failed to create address space");
        free_mem(user_process, seL4_CapNull, NULL, ep, ut);
        return -1;
    }

    mem_region_t *region = as_define_ipc_buff(user_process.addrspace);
    if (region == NULL) {
        ZF_LOGE("Failed to create ipc buffer region");
        free_mem(user_process, seL4_CapNull, region, ep, ut);
        return -1;
    }

    /* Create an IPC buffer */
    user_process.ipc_buffer_frame = clock_alloc_frame(user_process.addrspace, PROCESS_IPC_BUFFER);
    if (user_process.ipc_buffer_frame == NULL_FRAME) {
        ZF_LOGE("Failed to alloc ipc buffer ut");
        free_mem(user_process, seL4_CapNull, region, ep, ut);
        return -1;
    }
    user_process.ipc_buffer = frame_page(user_process.ipc_buffer_frame);

    // huh
    /* allocate a new slot in the target cspace which we will mint a badged endpoint cap into --
     * the badge is used to identify the process, which will come in handy when you have multiple
     * processes. */
    seL4_CPtr user_ep = cspace_alloc_slot(&user_process.cspace);
    if (user_ep == seL4_CapNull) {
        ZF_LOGE("Failed to alloc user ep slot");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* now mutate the cap, thereby setting the badge */
    err = cspace_mint(&user_process.cspace, user_ep, &cspace, ep, seL4_AllRights, APP_EP_BADGE);
    if (err) {
        ZF_LOGE("Failed to mint user ep");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Create a new TCB object */
    user_process.tcb_ut = alloc_retype(&user_process.tcb, seL4_TCBObject, seL4_TCBBits);
    if (user_process.tcb_ut == NULL) {
        ZF_LOGE("Failed to alloc tcb ut");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Configure the TCB */
    err = seL4_TCB_Configure(user_process.tcb,
                             user_process.cspace.root_cnode, seL4_NilData,
                             user_process.vspace, seL4_NilData, PROCESS_IPC_BUFFER,
                             user_process.ipc_buffer);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure new TCB");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Create scheduling context */
    user_process.sched_context_ut = alloc_retype(&user_process.sched_context, seL4_SchedContextObject,
                                                     seL4_MinSchedContextBits);
    if (user_process.sched_context_ut == NULL) {
        ZF_LOGE("Failed to alloc sched context ut");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Configure the scheduling context to use the first core with budget equal to period */
    err = seL4_SchedControl_Configure(sched_ctrl_start, user_process.sched_context, US_IN_MS, US_IN_MS, 0, 0);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to configure scheduling context");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* bind sched context, set fault endpoint and priority
     * In MCS, fault end point needed here should be in current thread's cspace.
     * NOTE this will use the unbadged ep unlike above, you might want to mint it with a badge
     * so you can identify which thread faulted in your fault handler */
    err = seL4_TCB_SetSchedParams(user_process.tcb, seL4_CapInitThreadTCB, seL4_MinPrio, APP_PRIORITY,
                                  user_process.sched_context, ep);
    if (err != seL4_NoError) {
        ZF_LOGE("Unable to set scheduling params");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Provide a name for the thread -- Helpful for debugging */
    NAME_THREAD(user_process.tcb, app_name);

    /* Read the ELF header from NFS */
    ZF_LOGI("\nStarting \"%s\"...\n", app_name);
    elf_t elf_file = {};
    unsigned long elf_size;
    char *elf_base = get_elf_data(app_name, &elf_size);
    if (elf_base == NULL) {
        ZF_LOGE("Unable to open or read %s from NFS", app_name);
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Ensure that the file is an elf file. */
    if (elf_newFile(elf_base, elf_size, &elf_file)) {
        ZF_LOGE("Invalid elf file");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* set up the stack */
    seL4_Word sp = init_process_stack(user_process, &cspace, seL4_CapInitThreadVSpace, &elf_file);
    if ((int) sp == -1) {
        ZF_LOGE("Failed to set up the stack");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Allocating a region for the heap */
    user_process.addrspace->heap_reg = as_define_heap(user_process.addrspace);
    if (user_process.addrspace->heap_reg == NULL) {
        ZF_LOGE("Failed to create the heap region");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* Map in the IPC buffer for the thread */
    err = sos_map_frame(&cspace, user_process.vspace, PROCESS_IPC_BUFFER, REGION_RD | REGION_WR,
                        user_process.ipc_buffer_frame, user_process.addrspace);
    if (err != 0) {
        ZF_LOGE("Unable to map IPC buffer for user app");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    /* load the elf image from nfs */
    err = elf_load(&cspace, user_process.vspace, &elf_file, user_process.addrspace);
    if (err) {
        ZF_LOGE("Failed to load elf image");
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

    init_threads(ep, ep, sched_ctrl_start, sched_ctrl_end);
    user_process.ep = ep;

    user_process.handler_thread = thread_create(handler_func, (void *) user_process.pid, user_process.pid, true, seL4_MaxPrio, seL4_CapNull, true);
    if (user_process.handler_thread == NULL) {
        ZF_LOGE("Could not create system call handler thread for %s\n", app_name);
        // will see, can probably put earlier for less frees
        return -1;
    }

    /* Initialise the per-process file descriptor table */
    char error;
    user_process.fdt = fdt_create(&error);
    if (error) {
        ZF_LOGE("Failed to initialise the file descriptor table");
        return -1;
    }

    open_file *file = file_create("console", O_WRONLY, netcon_send, deque);
    uint32_t fd;
    err = fdt_put(user_process.fdt, file, &fd); // initialise stdout
    if (err) {
        ZF_LOGE("Failed to initialise stdout");
        return -1;
    }
    err = fdt_put(user_process.fdt, file, &fd); // initialise stderr
    if (err) {
        ZF_LOGE("Failed to initialise stderr");
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
        free_mem(user_process, user_ep, region, ep, ut);
        return -1;
    }

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
    seL4_SetMR(0, pid);
}

void syscall_proc_getid(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d", SYSCALL_PROC_GETID);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_SetMR(0, user_process_list[badge].pid);
}