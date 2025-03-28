#include "sos_syscall.h"

#include <clock/clock.h>
#include <sos/gen_config.h>

#include "utils.h"
#include "frame_table.h"
#include "vmem_layout.h"
#include "network.h"
#include "console.h"
#include "thread_pool.h"
#include "buffercache.h"
#include "dentry.h"
#include "clock_replacement.h"

#include "boot_driver.h"
#include "sharedvm.h"

#define MAX_BATCH_SIZE 3
#ifdef CONFIG_SOS_FRAME_LIMIT
    bool buffercache_enable = CONFIG_SOS_FRAME_LIMIT != 0ul ? false : true;
#else
    bool buffercache_enable = true;
#endif

extern user_process_t *user_process_list;
extern sync_bin_sem_t *process_list_sem;
sync_bin_sem_t *nfs_sem = NULL;
bool console_open_for_read = false;

sync_bin_sem_t *data_sem = NULL;
sync_bin_sem_t *file_sem = NULL;

seL4_CPtr nfs_signal;

seL4_CPtr signal_cap;
seL4_CPtr reply;

extern seL4_CPtr clock_driver_ep;
extern seL4_CPtr sleep_signal;

bool handle_vm_fault(seL4_Word fault_addr, seL4_Word badge);

void init_semaphores(void) {
    data_sem = malloc(sizeof(sync_bin_sem_t));
    seL4_CPtr data_sem_cptr;
    ZF_LOGF_IF(!data_sem, "No memory for semaphore object");
    ut_t *sem_ut = alloc_retype(&data_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(data_sem, data_sem_cptr, 1);

    file_sem = malloc(sizeof(sync_bin_sem_t));
    seL4_CPtr file_sem_cptr;
    ZF_LOGF_IF(!file_sem, "No memory for semaphore object");
    ut_t *data_ut = alloc_retype(&file_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!data_ut, "No memory for notification");
    sync_bin_sem_init(file_sem, file_sem_cptr, 1);

    ut_t *nfs_ut = alloc_retype(&nfs_signal, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!nfs_ut, "No memory for notification");

    nfs_sem = malloc(sizeof(sync_bin_sem_t));
    seL4_CPtr nfs_sem_cptr;
    ZF_LOGF_IF(!nfs_sem, "No memory for semaphore object");
    nfs_ut = alloc_retype(&nfs_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!nfs_ut, "No memory for notification");
    sync_bin_sem_init(nfs_sem, nfs_sem_cptr, 1);

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

int netcon_send(UNUSED pid_t pid, open_file *file, char *data, UNUSED uint64_t offset, uint64_t len, void *callback, void *args) {
    int res = network_console_send(file->handle, data, len, callback, args);
    io_args *arg = (io_args *) args;
    struct task task = {len, res, arg->signal_cap};
    submit_task(task);
    return res;
}

static inline int perform_io_core(user_process_t user_process, uint16_t data_offset, uint64_t file_offset, uintptr_t vaddr,
                                  open_file *file, void *callback, bool read, uint16_t len, bool *cached) {
    pt_entry *entry = get_page(user_process.addrspace, vaddr);
    sync_bin_sem_wait(data_sem);
    pin_frame(entry->page.frame_ref);
    char *data = (char *)frame_data(entry->page.frame_ref);
    sync_bin_sem_post(data_sem);
    io_args *args = malloc(sizeof(io_args));
    *args = (io_args){.err = len, .buff = data + data_offset, .signal_cap = signal_cap,
                      .entry = entry, .cache_frames = NULL, .num_frames = 0, .cached = false};
    int res;
    if (read) {
        res = file->file_read(user_process.pid, file, data + data_offset, file_offset, len, callback, args);
    } else {
        res = file->file_write(user_process.pid, file, data + data_offset, file_offset, len, callback, args);
    }

    *cached = args->cached;
    if (*cached) {
        unpin_frame(entry->page.frame_ref);
        free(args);
    }
    return res;
}

static inline int cleanup_pending_requests(int outstanding_requests, size_t bytes_received) {
    bool failed = false;
    while (outstanding_requests > 0) {
        seL4_Recv(signal_cap, 0, reply);
        int result = seL4_GetMR(1);

        outstanding_requests--;
        bytes_received += result;

        if (result < 0) {
            failed = true;
        }
    }
    return failed ? -1 : (int)bytes_received;
}

static int perform_io(user_process_t user_process, size_t nbyte, uintptr_t vaddr, open_file *file, void *callback, bool read) {
    size_t bytes_received = 0;
    size_t bytes_left = nbyte;
    uint16_t outstanding_requests = 0;
    uint16_t offset = vaddr & (PAGE_SIZE_4K - 1);
    bool cached;

    do {
        /* Start the new batch of I/O requests. */
        while (outstanding_requests < MAX_BATCH_SIZE && bytes_left > 0) {
            uint16_t len = MIN(bytes_left, PAGE_SIZE_4K - offset);
            if (!vaddr_is_mapped(user_process.addrspace, vaddr)) {
                if (outstanding_requests > 0) {
                    break;
                }
                handle_vm_fault(vaddr, user_process.pid);
            }
            int res = perform_io_core(user_process, offset, file->offset + (nbyte - bytes_left), vaddr, file, callback, read, len, &cached);
            
            if (res == -1) {
                /* Error occurred */
                cleanup_pending_requests(outstanding_requests, bytes_received);
                return -1;
            } else if (res == -2) {
                /* Early exit. */
                return cleanup_pending_requests(outstanding_requests, bytes_received);
            }
            
            bytes_left -= res;
            vaddr += res;
            offset = 0;
            
            if (cached) {
                bytes_received += res;
            } else {
                outstanding_requests++;
            }

            if (res < len) {
                /* If we got partial or non-existent data then exit early (we probably hit the EOF). */
                break;
            }
        }

        /* Collect and process the outstanding results. */
        while (outstanding_requests > 0) {
            seL4_Recv(signal_cap, 0, reply);
            int target = seL4_GetMR(0);
            int result = seL4_GetMR(1);
            
            if (result < 0) {
                cleanup_pending_requests(outstanding_requests, bytes_received);
                return -1;
            }
            
            bytes_received += result;
            outstanding_requests--;
            
            if (target != result) {
                return cleanup_pending_requests(outstanding_requests, bytes_received);
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
    seL4_Word vaddr = seL4_GetMR(1);
    int path_len = seL4_GetMR(2) + 1;
    int mode = seL4_GetMR(3);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

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
        execute_io nfs_write = buffercache_enable ? buffercache_write : nfs_pwrite_file;
        execute_io nfs_read = buffercache_enable ? buffercache_read : nfs_pread_file;
        file = dentry_check(file_path, mode, nfs_write, nfs_read);
        if (file->handle == NULL) {
            io_args args = {.signal_cap = nfs_signal};
            if (nfs_open_file(file, nfs_async_open_cb, &args) < 0) {
                file_destroy(file);
                seL4_SetMR(0, -1);
                return;
            }
            file->handle = args.buff;

            sos_stat_t stat;
            args = (io_args){0, &stat, nfs_signal, NULL, NULL, 0, 0};
            if (nfs_stat_file(file_path, nfs_async_stat_cb, &args)) {
                seL4_SetMR(0, -1);
                return;
            }
            if (args.err < 0) {
                seL4_SetMR(0, -1);
                return;
            }
            file->size = stat.st_size;

            int res = dentry_write(file);
            ZF_LOGE_IF(res == -1, "Failed to add to dentry cache");
        }
    } else {
        sync_bin_sem_wait(file_sem);
        /* Check if stdin is already open by another process */
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
    int close_fd = seL4_GetMR(1);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    open_file *found = fdt_get_file(user_process.fdt, close_fd);
    if (found == NULL) {
        seL4_SetMR(0, -1);
        return;
    } else if (strcmp(found->path, "console")) {
        dentry_mark_closed(found);
        buffercache_flush(found);
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
    /* Receive a fd from sos.c */
    int read_fd = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    int nbyte = seL4_GetMR(3);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    open_file *found = fdt_get_file(user_process.fdt, read_fd);
    if (found == NULL || found->mode == O_WRONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
        return;
    }

    sync_bin_sem_wait(nfs_sem);
    int res = perform_io(user_process, nbyte, vaddr, found, nfs_buffercache_read_rdcb, true);
    if (res > 0) {
        found->offset += res;
    }
    sync_bin_sem_post(nfs_sem);
    seL4_SetMR(0, res);
}

void syscall_sos_write(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* Construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive fd, virtual address, and number of bytes from sos.c */
    int write_fd = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    size_t nbyte = seL4_GetMR(3);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    /* Find the file associated with the file descriptor */
    open_file *found = fdt_get_file(user_process.fdt, write_fd);
    if (found == NULL || found->mode == O_RDONLY) {
        /* Set the reply message to be an error value and return early */
        seL4_SetMR(0, -1);
        return;
    }

    sync_bin_sem_wait(nfs_sem);
    int res = perform_io(user_process, nbyte, vaddr, found, nfs_buffercache_read_wrcb, false);
    if (res > 0) {
        found->offset += res;
        if (found->offset > found->size) {
            found->size = found->offset;
        }
    }
    sync_bin_sem_post(nfs_sem);
    seL4_SetMR(0, res);
}

void syscall_sos_usleep(seL4_MessageInfo_t *reply_msg, UNUSED seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_USLEEP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 0);

    user_process_t clock_driver = user_process_list[0];

    seL4_SetMR(0, timer_RegisterTimer);
    uint64_t delay = seL4_GetMR(1);
    seL4_SetMR(1, delay);
    seL4_Send(clock_driver_ep, seL4_MessageInfo_new(0, 0, 0, 2));
    seL4_Wait(sleep_signal, 0);
}

inline void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_TIME_STAMP);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the reply message to be the timestamp since booting in microseconds */
    seL4_SetMR(0, timer_MicroTimestamp);
    seL4_Call(clock_driver_ep, seL4_MessageInfo_new(0, 0, 0, 1));
    seL4_SetMR(0, seL4_GetMR(0));
}

void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, seL4_Word badge)
{
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_STAT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word path_vaddr = seL4_GetMR(1);
    seL4_Word buf_vaddr = seL4_GetMR(2);
    size_t path_len = seL4_GetMR(3) + 1;

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

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
        io_args args = {0, &stat, nfs_signal, NULL, NULL, 0, 0};
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
    int pos = seL4_GetMR(1);
    seL4_Word vaddr = seL4_GetMR(2);
    size_t nbyte = seL4_GetMR(3);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

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

void syscall_sos_share_vm(seL4_MessageInfo_t *reply_msg, seL4_Word badge) {
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SOS_SHARE_VM);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word adr = seL4_GetMR(1);
    size_t size = seL4_GetMR(2);
    int writable = seL4_GetMR(3);

    if ((adr % PAGE_SIZE_4K) || (size % PAGE_SIZE_4K)) {
        seL4_SetMR(0, -1);
        return;
    } else if (vaddr_is_mapped(user_process_list[badge].addrspace, adr)) {
        seL4_SetMR(0, -1);
        return;
    } else if (check_overlap(user_process_list[badge].addrspace, adr, size)) {
        seL4_SetMR(0, -1);
        return;
    }

    uint64_t perms = REGION_RD;
    if (writable) {
        perms |= REGION_WR;
    }

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    mem_region_t *reg = insert_shared_region(user_process.addrspace, (size_t) adr, size, perms);
    if (reg == NULL) {
        seL4_SetMR(0, -1);
        return;
    }

    seL4_SetMR(0, add_shared_region(user_process, adr, size, perms));
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
    uintptr_t newbrk = seL4_GetMR(1);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

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
    /* For malloc, we only care about the first 3 arguments of mmap. Even the 3rd one
     * we can technically hard-code, but we'll take it in case we want to extend later.*/
    seL4_Word addr = PAGE_ALIGN(seL4_GetMR(1), PAGE_SIZE_4K);
    size_t length = PAGE_ALIGN(seL4_GetMR(2), PAGE_SIZE_4K);
    int prot = seL4_GetMR(3);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    if (!addr) {
        /* Find the first slot in the user address space where we can insert this region. */
        mem_region_t *mmap_region = insert_region_at_free_slot(user_process.addrspace, length, prot);
        if (mmap_region == NULL) {
            seL4_SetMR(0, -1);
        } else {
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

    if (l4_table[l4_i].valid) {
        sync_bin_sem_wait(data_sem);
        free_frame(l4_table[l4_i].page.frame_ref);
        sync_bin_sem_post(data_sem);
        seL4_CPtr frame_cptr = l4_table[l4_i].page.frame_cptr;
        seL4_ARM_Page_Unmap(frame_cptr);
        free_untype(&frame_cptr, NULL);
    } else if (l4_table[l4_i].swapped) {
        mark_block_free(l4_table[l4_i].swap_map_index);
    }
    l4_table[l4_i] = (pt_entry){0};
}

void syscall_sys_munmap(seL4_MessageInfo_t *reply_msg, seL4_Word badge) {
    ZF_LOGV("syscall: some thread made syscall %d!\n", SYSCALL_SYS_MUNMAP);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word addr = PAGE_ALIGN(seL4_GetMR(1), PAGE_SIZE_4K);
    size_t length = PAGE_ALIGN(seL4_GetMR(2), PAGE_SIZE_4K);

    sync_bin_sem_wait(process_list_sem);
    user_process_t user_process = user_process_list[badge];
    sync_bin_sem_post(process_list_sem);

    /* Assume the given addr is the start of the address space which is enough for malloc + free:
     * The free() function frees the memory space pointed to by ptr, which must have been returned
     * by a previous call to malloc(), calloc() or realloc(). Otherwise, or if free(ptr) has already
     * been called before, undefined behavior occurs. If ptr is NULL, no operation is performed. */
    mem_region_t tmp = { .base = addr };
    mem_region_t *reg = sglib_mem_region_t_find_member(user_process.addrspace->region_tree, &tmp);
    if (reg == NULL) {
        seL4_SetMR(0, -1);
        return;
    }

    /* Remove the frames belonging to the mmap region. */
    for (size_t bytes_left = length; bytes_left > 0; bytes_left -= PAGE_SIZE_4K) {
        if (!vaddr_check(user_process, addr)) {
            seL4_SetMR(0, -1);
            return;
        }

        free_page(user_process, addr);
        addr += PAGE_SIZE_4K;
    }

    /* Remove the mmapped memory region. */
    if (length >= reg->size) {
        remove_region(user_process.addrspace, reg->base);
    } else {
        reg->base += length;
    }

    seL4_SetMR(0, 0);
}