#include "sos_syscall.h"

#include <clock/clock.h>
#include <sos/gen_config.h>

#include "utils.h"
#include "frame_table.h"
#include "vmem_layout.h"
#include "network.h"
#include "console.h"
#include "thread_pool.h"

#ifdef CONFIG_SOS_FRAME_LIMIT
    #define MAX_BATCH_SIZE (CONFIG_SOS_FRAME_LIMIT != 0ul ? 1 : 3)
#else
    #define MAX_BATCH_SIZE 3
#endif

extern user_process_t *user_process_list;
bool console_open_for_read = false;

seL4_CPtr data_sem_cptr;
sync_bin_sem_t *data_sem = NULL;

seL4_CPtr file_sem_cptr;
sync_bin_sem_t *file_sem = NULL;

seL4_CPtr nfs_signal;
seL4_CPtr sleep_signal;

seL4_CPtr signal_cap;
seL4_CPtr reply;

bool handle_vm_fault(seL4_Word fault_addr, seL4_Word badge);

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

    ut_t *nfs_ut = alloc_retype(&nfs_signal, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!nfs_ut, "No memory for notification");
    ut_t *sleep_ut = alloc_retype(&sleep_signal, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sleep_ut, "No memory for notification");

    alloc_retype(&signal_cap, seL4_EndpointObject, seL4_EndpointBits);
    ut_t *reply_ut = alloc_retype(&reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }
    initialise_thread_pool(netcon_reply);
}

static inline bool vaddr_check(user_process_t user_process, seL4_Word vaddr) {
    return vaddr_is_mapped(user_process.addrspace, vaddr) || handle_vm_fault(vaddr, user_process.pid);
}

static inline pt_entry *get_page(addrspace_t *as, seL4_Word vaddr) {
    uint16_t l1_i = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_i = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_i = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_i = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    return &as->page_table[l1_i].l2[l2_i].l3[l3_i].l4[l4_i];
}

static inline void wakeup(UNUSED uint32_t id, UNUSED void* data)
{
    seL4_Signal(sleep_signal);
}

int netcon_send(open_file *file, char *data, UNUSED uint64_t offset, uint64_t len, void *callback, void *args) {
    int res = network_console_send(file->handle, data, len, callback, args);
    io_args *arg = (io_args *) args;
    struct task task = {len, res, arg->signal_cap};
    submit_task(task);
    return res;
}

static inline int perform_io_core(user_process_t user_process, uint16_t data_offset, uint64_t file_offset, uintptr_t vaddr,
                                  open_file *file, void *callback, bool read, uint16_t len) {
    if (!vaddr_check(user_process, vaddr)) {
        return -1;
    }

    pt_entry *entry = get_page(user_process.addrspace, vaddr);
    entry->pinned = 1;
    sync_bin_sem_wait(data_sem);
    char *data = (char *)frame_data(entry->page.frame_ref);
    sync_bin_sem_post(data_sem);
    io_args *args = malloc(sizeof(io_args));
    *args = (io_args){.err = len, .buff = data + data_offset, .signal_cap = signal_cap, .entry = entry};
    int res;
    if (read) {
        res = file->file_read(file, data + data_offset, file_offset, len, callback, args);
    } else {
        res = file->file_write(file, data + data_offset, file_offset, len, callback, args);
    }

    return res < 0 ? -1 : res;
}

static inline int cleanup_pending_requests(int outstanding_requests) {
    while (outstanding_requests > 0) {
        seL4_Recv(signal_cap, 0, reply);
        outstanding_requests--;
    }
    return -1;
}

static int perform_io(user_process_t user_process, size_t nbyte, uintptr_t vaddr, open_file *file, void *callback, bool read) {
    size_t bytes_received = 0;
    size_t bytes_left = nbyte;
    uint16_t outstanding_requests = 0;
    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);

    do {
        /* Start the new batch of I/O requests. */
        while (outstanding_requests < MAX_BATCH_SIZE && bytes_left > 0) {
            uint16_t len = MIN(bytes_left, PAGE_SIZE_4K - offset);
            int res = perform_io_core(user_process, offset, file->offset + (nbyte - bytes_left), vaddr, file, callback, read, len);
            
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
            seL4_Recv(signal_cap, 0, reply);
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

int perform_cpy(user_process_t user_process, size_t nbyte, uintptr_t vaddr, bool data_to_buff, void *buff) {
    size_t bytes_left = nbyte;
    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);

    while (bytes_left > 0) {
        uint16_t len = MIN(bytes_left, PAGE_SIZE_4K - offset);
        if (!vaddr_check(user_process, vaddr)) {
            return -1;
        }

        sync_bin_sem_wait(data_sem);
        char *data = (char *)frame_data(get_page(user_process.addrspace, vaddr)->page.frame_ref);
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

void syscall_sos_open(seL4_MessageInfo_t *reply_msg, seL4_Word badge) 
{
    ZF_LOGV("syscall: thread example made syscall %d!\n", SYSCALL_SOS_OPEN);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

    seL4_Word vaddr = seL4_GetMR(1);
    int path_len = seL4_GetMR(2) + 1;
    int mode = seL4_GetMR(3);

    if ((mode != O_WRONLY) && (mode != O_RDONLY) && (mode != O_RDWR)) {
        seL4_SetMR(0, -1);
        return;
    }

    char *file_path = malloc(path_len);
    int res = perform_cpy(user_process, path_len, vaddr, true, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }
    file_path[path_len - 1] = '\0';

    open_file *file;
    if (strcmp(file_path, "console")) {
        file = file_create(file_path, mode, nfs_pwrite_file, nfs_pread_file);
        io_args args = {.signal_cap = nfs_signal};
        if (nfs_open_file(file, nfs_async_open_cb, &args) < 0) {
            file_destroy(file);
            seL4_SetMR(0, -1);
            return;
        }
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
    if (!strcmp(file->path, "console") && file->mode != O_WRONLY) {
        fdt_put_console(user_process.fdt, file, &fd);
        seL4_SetMR(0, (int) fd);
        return;
    }
    int err = fdt_put(user_process.fdt, file, &fd);
    seL4_SetMR(0, err ? -1 : (int) fd);
}

void syscall_sos_close(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_CLOSE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];
    int close_fd = seL4_GetMR(1);

    open_file *found = fdt_get_file(user_process.fdt, close_fd);
    if (found == NULL) {
        seL4_SetMR(0, -1);
        return;
    } else if (strcmp(found->path, "console")) {
        io_args args = {.signal_cap = nfs_signal};
        if (nfs_close_file(found, nfs_async_close_cb, &args) < 0) {
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

void syscall_sos_read(seL4_MessageInfo_t *reply_msg, seL4_Word badge) 
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_READ);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];
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

    int res = perform_io(user_process, nbyte, vaddr, found, nfs_async_read_cb, true);
    if (res > 0) {
        found->offset += res;
    }
    seL4_SetMR(0, res);
}

void syscall_sos_write(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* Construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

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
    int res = perform_io(user_process, nbyte, vaddr, found, nfs_async_write_cb, false);
    if (res > 0) {
        found->offset += res;
    }
    seL4_SetMR(0, res);
}

void syscall_sos_usleep(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_USLEEP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    register_timer(seL4_GetMR(1), wakeup, NULL);

    seL4_Wait(sleep_signal, 0);
}

inline void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_TIME_STAMP);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the reply message to be the timestamp since booting in microseconds */
    seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
}

void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_STAT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word path_vaddr = seL4_GetMR(1);
    seL4_Word buf_vaddr = seL4_GetMR(2);
    size_t path_len = seL4_GetMR(3) + 1;

    user_process_t user_process = user_process_list[badge];

    /* Perform stat operation. We don't assume it's only on 1 page */
    char *file_path = malloc(path_len);
    file_path[path_len - 1] = '\0';
    int res = perform_cpy(user_process, path_len, path_vaddr, true, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }

    sos_stat_t stat = {ST_SPECIAL, 0, 0, 0, 0};
    if (strcmp(file_path, "console")) {
        io_args args = {0, &stat, nfs_signal, NULL};
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
    
    res = perform_cpy(user_process, sizeof(sos_stat_t), buf_vaddr, false, &stat);
    seL4_SetMR(0, res < 0 ? res : 0);
}

void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_GETDIRENT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];
    int pos = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    size_t nbyte = seL4_GetMR(3);

    io_args args = {.err = 0, .signal_cap = nfs_signal};
    if (nfs_open_dir(nfs_async_opendir_cb, &args)) {
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
    int res = perform_cpy(user_process, size, vaddr, false, name);

    seL4_Word new_vaddr = vaddr + size;
    unsigned char *data = frame_data(get_page(user_process.addrspace, vaddr)->page.frame_ref);
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

inline void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_BRK);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

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

void syscall_sys_mmap(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_MMAP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

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

static inline void free_page(user_process_t user_process, seL4_Word vaddr) {
    uint16_t l1_i = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_i = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_i = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_i = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    pt_entry *l4_table = user_process.addrspace->page_table[l1_i].l2[l2_i].l3[l3_i].l4;

    sync_bin_sem_wait(data_sem);
    free_frame(l4_table[l4_i].page.frame_ref);
    sync_bin_sem_post(data_sem);
    seL4_CPtr frame_cptr = l4_table[l4_i].page.frame_cptr;
    seL4_ARM_Page_Unmap(frame_cptr);
    free_untype(&frame_cptr, NULL);
    l4_table[l4_i] = (pt_entry){0};
}

void syscall_sys_munmap(seL4_MessageInfo_t *reply_msg, seL4_Word badge) {
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_MUNMAP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    user_process_t user_process = user_process_list[badge];

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
        if (!vaddr_check(user_process, vaddr)) {
            seL4_SetMR(0, -1);
            return;
        }

        free_page(user_process, vaddr);
        vaddr += PAGE_SIZE_4K;
    }

    seL4_SetMR(0, 0);
}