#include "sos_syscall.h"

extern struct user_process user_process;
bool console_open_for_read = false;

seL4_CPtr data_sem_cptr;
sync_bin_sem_t *data_sem = NULL;

seL4_CPtr file_sem_cptr;
sync_bin_sem_t *file_sem = NULL;

seL4_CPtr nfs_sem_cptr;
sync_bin_sem_t *nfs_sem = NULL;

seL4_CPtr io_ep;
seL4_CPtr reply;

bool handle_vm_fault(seL4_Word fault_addr);

void init_semaphores(void) {
    data_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!data_sem, "No memory for semaphore object");
    ut_t *sem_ut = alloc_retype(&data_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(data_sem, data_sem_cptr, 1);

    file_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!file_sem, "No memory for semaphore object");
    ut_t *data_ut = alloc_retype(&file_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!data_ut, "No memory for notification");
    sync_bin_sem_init(file_sem, file_sem_cptr, 1);

    nfs_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!nfs_sem, "No memory for semaphore object");
    ut_t *nfs_ut = alloc_retype(&nfs_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!nfs_ut, "No memory for notification");
    sync_bin_sem_init(nfs_sem, nfs_sem_cptr, 0);

    alloc_retype(&io_ep, seL4_EndpointObject, seL4_EndpointBits);
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }
    initialise_thread_pool(netcon_reply);
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

    return l4_pt[l4_index].valid;
}

static inline bool vaddr_check(seL4_Word vaddr) {
    /* If the vaddr is not in a valid region we error out. Then if the address is not already
     * mapped and vm_fault returns an error when trying to map it, we also error out.*/
    return vaddr_is_mapped(vaddr) || handle_vm_fault(vaddr);
}

static inline frame_ref_t get_frame(seL4_Word vaddr) {
    uint16_t l1_i = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_i = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_i = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_i = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    return user_process.addrspace->page_table[l1_i].l2[l2_i].l3[l3_i].l4[l4_i].page.frame_ref;
}

static inline void wakeup(UNUSED uint32_t id, void* data)
{
    sync_bin_sem_t *sleep_sem = (sync_bin_sem_t *) data;
    sync_bin_sem_post(sleep_sem);
}

static inline int perform_io_core(uint16_t data_offset, uint64_t file_offset, uintptr_t vaddr,
                                  open_file *file, void *callback, bool read, uint16_t len) {
    if (!vaddr_check(vaddr)) {
        return -1;
    }

    sync_bin_sem_wait(data_sem);
    char *data = (char *)frame_data(get_frame(vaddr));
    nfs_args *args = malloc(sizeof(nfs_args));
    *args = (nfs_args){.err = len, .buff = data + data_offset, .sem = NULL, .io_ep = io_ep};
    int res;
    if (read) {
        res = file->file_read(file, data + data_offset, file_offset, len, callback, args);
    } else {
        res = file->file_write(file, data + data_offset, file_offset, len, callback, args);
    }
    sync_bin_sem_post(data_sem);

    return res < 0 ? -1 : res;
}

static inline int cleanup_pending_requests(int outstanding_requests) {
    while (outstanding_requests > 0) {
        seL4_Recv(io_ep, 0, reply);
        outstanding_requests--;
    }
    return -1;
}

static int perform_io(size_t nbyte, uintptr_t vaddr, open_file *file, void *callback, bool read) {
    #define MAX_BATCH_SIZE 3
    size_t bytes_received = 0;
    size_t bytes_left = nbyte;
    uint16_t outstanding_requests = 0;
    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);

    do {
        /* Start the new batch of I/O requests. */
        while (outstanding_requests < MAX_BATCH_SIZE && bytes_left > 0) {
            uint16_t len = MIN(bytes_left, PAGE_SIZE_4K - offset);
            int res = perform_io_core(offset, file->offset + (nbyte - bytes_left), vaddr, file, callback, read, len);
            
            if (res < 0) {
                return cleanup_pending_requests(outstanding_requests);
            }
            
            outstanding_requests++;
            bytes_left -= res;
            vaddr += res;
            offset = 0;
            
            /* If we got partial or non-existent data then exit early (we probably hit the EOF). */
            if (res != len) {
                break;
            }
        }

        /* Collect and process the outstanding results. */
        while (outstanding_requests > 0) {
            seL4_Recv(io_ep, 0, reply);
            int target = seL4_GetMR(0);
            int result = seL4_GetMR(1);
            
            if (result < 0) {
                return cleanup_pending_requests(outstanding_requests);
            }
            
            bytes_received += result;
            outstanding_requests--;
            
            if (target != result) {
                cleanup_pending_requests(outstanding_requests);
                return bytes_received;
            }
        }
    } while (bytes_left > 0);

    return bytes_received;
}

static int perform_cpy(size_t nbyte, uintptr_t vaddr, bool data_to_buff, void *buff) {
    size_t bytes_left = nbyte;
    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);

    while (bytes_left > 0) {
        uint16_t len = MIN(bytes_left, PAGE_SIZE_4K - offset);

        if (!vaddr_check(vaddr)) {
            return -1;
        }

        sync_bin_sem_wait(data_sem);
        char *data = (char *)frame_data(get_frame(vaddr));
        if (data_to_buff) {
            memcpy(buff + (nbyte - len), data + offset, len);
        } else {
            memcpy(data + offset, buff + (nbyte - len), len);
        }
        sync_bin_sem_post(data_sem);

        // Update offset, virtual address, and bytes left
        bytes_left -= len;
        vaddr += len;
        offset = 0;
    }
    return nbyte - bytes_left;
}

int netcon_send(open_file *file, char *data, UNUSED uint64_t offset, uint64_t len, void *callback, void *args) {
    int res = network_console_send(file->handle, data, len, callback, args);
    nfs_args *arg = (nfs_args *) args;
    struct task task = {len, res, arg->io_ep};
    submit_task(task);
    return res;
}

void syscall_sos_open(seL4_MessageInfo_t *reply_msg) 
{
    seL4_Word vaddr = seL4_GetMR(1);
    int path_len = seL4_GetMR(2);
    int mode = seL4_GetMR(3);

    ZF_LOGV("syscall: thread example made syscall %d!\n", SYSCALL_SOS_OPEN);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    if ((mode != O_WRONLY) && (mode != O_RDONLY) && (mode != O_RDWR)) {
        seL4_SetMR(0, -1);
        return;
    }

    char *file_path = malloc(path_len);
    int res = perform_cpy(path_len, vaddr, true, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }

    open_file *file;
    if (strcmp(file_path, "console")) {
        nfs_args args = {.sem = nfs_sem};
        if (nfs_open_file(file_path, mode, nfs_async_open_cb, &args) < 0) {
            seL4_SetMR(0, -1);
            return;
        }
        file = file_create(file_path, mode, nfs_pwrite_file, nfs_pread_file);
        file->handle = args.buff;
    } else {
        sync_bin_sem_wait(file_sem);
        if (console_open_for_read && mode != O_WRONLY) {
            sync_bin_sem_post(file_sem);
            seL4_SetMR(0, -1);
            return;
        } else if (mode != O_WRONLY) {
            console_open_for_read = true;
        }
        sync_bin_sem_post(file_sem);
        file = file_create(file_path, mode, netcon_send, deque);
    }

    uint32_t fd;
    int err = fdt_put(user_process.fdt, file, &fd);
    seL4_SetMR(0, err ? -1 : (int) fd);
}

void syscall_sos_close(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_CLOSE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int close_fd = seL4_GetMR(1);

    open_file *found = fdt_get_file(user_process.fdt, close_fd);
    if (found == NULL) {
        seL4_SetMR(0, -1);
        return;
    } else if (strcmp(found->path, "console")) {
        nfs_args args = {.sem = nfs_sem};
        if (nfs_close_file(found->handle, nfs_async_close_cb, &args) < 0) {
            seL4_SetMR(0, -1);
            return;
        }
        if (args.err) {
            seL4_SetMR(0, -1);
            return;
        }
    } else if (found->mode != O_WRONLY) {
        sync_bin_sem_wait(file_sem);
        console_open_for_read = false;
        sync_bin_sem_post(file_sem);
    }
    
    fdt_remove(user_process.fdt, close_fd);
    seL4_SetMR(0, 0);
}

void syscall_sos_read(seL4_MessageInfo_t *reply_msg) 
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_READ);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive a fd from sos.c */
    int read_fd = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    int nbyte = seL4_GetMR(3);

    open_file *found = fdt_get_file(user_process.fdt, read_fd);
    if (found == NULL || found->mode == O_WRONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
        return;
    }

    int res = perform_io(nbyte, vaddr, found, nfs_async_read_cb, true);
    if (res > 0) {
        found->offset += res;
    }
    seL4_SetMR(0, res);
}

void syscall_sos_write(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* Construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    /* Receive fd, virtual address, and number of bytes from sos.c */
    int write_fd = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    size_t nbyte = seL4_GetMR(3);

    /* Find the file associated with the file descriptor */
    open_file *found = fdt_get_file(user_process.fdt, write_fd);
    if (found == NULL || found->mode == O_RDONLY) {
        /* Set the reply message to be an error value and return early */
        seL4_SetMR(0, -1);
        return;
    }
    int res = perform_io(nbyte, vaddr, found, nfs_async_write_cb, false);
    if (res > 0) {
        found->offset += res;
    }
    seL4_SetMR(0, res);
}

void syscall_sos_usleep(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_USLEEP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    seL4_CPtr sleep_sem_cptr;
    sync_bin_sem_t sleep_sem;
    ut_t *sleep_ut = alloc_retype(&sleep_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sleep_ut, "No memory for notification");
    sync_bin_sem_init(&sleep_sem, sleep_sem_cptr, 0);

    register_timer(seL4_GetMR(1), wakeup, (void *) &sleep_sem);

    sync_bin_sem_wait(&sleep_sem);
    free_untype(&sleep_sem_cptr, sleep_ut);
}

inline void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_TIME_STAMP);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the reply message to be the timestamp since booting in microseconds */
    seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
}

void syscall_sos_stat(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_STAT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word path_vaddr = seL4_GetMR(1);
    seL4_Word buf_vaddr = seL4_GetMR(2);
    size_t path_len = seL4_GetMR(3);

    /* Perform stat operation. We don't assume it's only on 1 page */
    char *file_path = calloc(path_len, sizeof(char));
    int res = perform_cpy(path_len, path_vaddr, true, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }

    sos_stat_t stat = {ST_SPECIAL, 0, 0, 0, 0};
    if (strcmp(file_path, "console")) {
        nfs_args args = {0, &stat, nfs_sem, 0};
        if (nfs_stat_file(file_path, nfs_async_stat_cb, &args)) {
            seL4_SetMR(0, -1);
            return;
        }
        if (args.err < 0) {
            seL4_SetMR(0, -1);
            return;
        }
        stat.st_fmode >>= 6;
    }
    
    res = perform_cpy(sizeof(sos_stat_t), buf_vaddr, false, &stat);
    seL4_SetMR(0, res < 0 ? res : 0);
}

void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_GETDIRENT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int pos = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    size_t nbyte = seL4_GetMR(3);

    nfs_args args = {.err = 0, .sem = nfs_sem};
    if (nfs_open_dir(nfs_async_opendir_cb, &args)) {
        seL4_SetMR(0, -1);
        return;
    }
    if (args.err) {
        seL4_SetMR(0, -1);
        return;
    }

    struct nfsdirent *nfsdirent = nfs_read_dir(args.buff);
    int i = 0;
    while (nfsdirent->next != NULL && i < pos) {
        nfsdirent = nfsdirent->next;
        i++;
    }

    char* name = nfsdirent->name;
    if (!strcmp(nfsdirent->name, "..")) {
        name = "console";
    } else if (!strcmp(nfsdirent->name, "pagefile")) {
        seL4_SetMR(0, -2);
        return;
    } else if (i + 1 == pos && nfsdirent->next == NULL) {
        seL4_SetMR(0, 0);
        return;
    } else if (i < pos && nfsdirent->next == NULL) {
        seL4_SetMR(0, -1);
        return;
    }

    size_t path_len = strlen(name);
    size_t size = nbyte < path_len ? nbyte : path_len;
    int res = perform_cpy(size, vaddr, false, name);

    seL4_Word new_vaddr = vaddr + size;
    unsigned char *data = frame_data(get_frame(new_vaddr));
    data[new_vaddr & (PAGE_SIZE_4K - 1)] = 0;
    nfs_close_dir(args.buff);
    
    seL4_SetMR(0, res);
}

void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number)
{
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    ZF_LOGV("System call %lu not implemented\n", syscall_number);
    /* Reply -1 to an unimplemented syscall */
    seL4_SetMR(0, -1);
}

inline void syscall_sys_brk(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_BRK);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    uintptr_t newbrk = seL4_GetMR(1);
    if (newbrk <= 0) {
        seL4_SetMR(0, PROCESS_HEAP_START);        
    } else if (newbrk >= ALIGN_DOWN(user_process.addrspace->above_heap->base, PAGE_SIZE_4K)) {
        seL4_SetMR(0, 0);
    } else {
        user_process.addrspace->heap_reg->size = newbrk - PROCESS_HEAP_START;
        seL4_SetMR(0, newbrk);
    }
}

void syscall_sys_mmap(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_MMAP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    /* For malloc, we only care about the first 3 arguments of mmap. Even the 3rd one
     * we can technically hard-code, but we'll take it in case we want to extend later.*/
    seL4_Word addr = PAGE_ALIGN(seL4_GetMR(1), PAGE_SIZE_4K);
    size_t length = PAGE_ALIGN(seL4_GetMR(2), PAGE_SIZE_4K);
    int prot = seL4_GetMR(3);

    if (!addr) {
        /* Find the first slot in the user address space where we can insert this region. */
        mem_region_t *mmap_region = insert_region_at_free_slot(user_process.addrspace, length, prot);
        if (mmap_region == NULL) {
            seL4_SetMR(0, -1);
        } else {
            assert(mmap_region->base != 0);
            seL4_SetMR(0, mmap_region->base);
        }
    } else {
        ZF_LOGE("This part of mmap is not implemented!\n");
        seL4_SetMR(0, -1);
    }
}

static inline void free_page(seL4_Word vaddr) {
    uint16_t l1_i = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_i = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_i = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_i = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    pt_entry *l4_table = user_process.addrspace->page_table[l1_i].l2[l2_i].l3[l3_i].l4;

    sync_bin_sem_wait(data_sem);
    free_frame(l4_table[l4_i].page.frame_ref);
    sync_bin_sem_post(data_sem);
    seL4_CPtr frame_cptr = l4_table[l4_i].page.frame_cptr;
    seL4_ARM_PageTable_Unmap(frame_cptr);
    free_untype(&frame_cptr, NULL);
    l4_table[l4_i] = (pt_entry){0};
}

void syscall_sys_munmap(seL4_MessageInfo_t *reply_msg) {
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_MUNMAP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    seL4_Word addr = PAGE_ALIGN(seL4_GetMR(1), PAGE_SIZE_4K);
    size_t length = PAGE_ALIGN(seL4_GetMR(2), PAGE_SIZE_4K);

    /* Assume the given addr is the start of the address space which is enough for malloc + free:
     * The free() function frees the memory space pointed to by ptr, which must have been returned
     * by a previous call to malloc(), calloc() or realloc(). Otherwise, or if free(ptr) has already
     * been called before, undefined behavior occurs. If ptr is NULL, no operation is performed. */
    mem_region_t tmp = { .base = addr };
    mem_region_t *reg = sglib_mem_region_t_find_member(user_process.addrspace->region_tree, &tmp);
    if (reg != NULL) {
        seL4_SetMR(0, -1);
        return;
    }

    /* Remove the mmapped memory region. */
    if (length >= reg->size) {
        remove_region(user_process.addrspace, reg->base);
    } else {
        reg->base += length;
    }

    /* Remove the page and its contents. */
    size_t vaddr = addr;
    for (size_t bytes_left = length; bytes_left > 0; bytes_left -= PAGE_SIZE_4K) {
        if (!vaddr_check(vaddr)) {
            seL4_SetMR(0, -1);
            return;
        }

        free_page(vaddr);
        vaddr += PAGE_SIZE_4K;
    }

    seL4_SetMR(0, 0);
}