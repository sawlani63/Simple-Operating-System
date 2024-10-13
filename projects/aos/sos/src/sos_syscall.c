#include "sos_syscall.h"

#define READ_IO 0x1
#define WRITE_IO 0x2
#define DATA_TO_BUFF 0x4
#define BUFF_TO_DATA 0x8

extern struct user_process user_process;
bool console_open_for_read = false;

seL4_CPtr data_sem_cptr;
sync_bin_sem_t *data_sem = NULL;

seL4_CPtr file_sem_cptr;
sync_bin_sem_t *file_sem = NULL;

seL4_CPtr nfs_sem_cptr;
sync_bin_sem_t *nfs_sem = NULL;

bool handle_vm_fault(seL4_Word fault_addr);

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

    return (frame_ref_t)(l4_pt[l4_index] & MASK(19)) != NULL_FRAME;
}

static bool vaddr_check(seL4_Word vaddr) {
    /* If the vaddr is not in a valid region we error out. Then if the address is not already
     * mapped and vm_fault returns an error when trying to map it, we also error out.*/
    return vaddr_is_mapped(vaddr) || handle_vm_fault(vaddr);
}

static frame_ref_t l4_frame(pt_entry *l4_pt, uint16_t l4_index) {
    return (frame_ref_t)(l4_pt[l4_index] & MASK(19));
}

static frame_ref_t get_frame(seL4_Word vaddr) {
    uint16_t l1_index = (vaddr >> 39) & MASK(9); /* Top 9 bits */
    uint16_t l2_index = (vaddr >> 30) & MASK(9); /* Next 9 bits */
    uint16_t l3_index = (vaddr >> 21) & MASK(9); /* Next 9 bits */
    uint16_t l4_index = (vaddr >> 12) & MASK(9); /* Next 9 bits */
    return l4_frame(user_process.addrspace->page_table[l1_index].l2[l2_index].l3[l3_index].l4,
                    l4_index);
}

static void wakeup(UNUSED uint32_t id, void* data)
{
    struct task *args = (struct task *) data;
    seL4_NBSend(args->reply, seL4_MessageInfo_new(0, 0, 0, 0));
    free_untype(&args->reply, args->reply_ut);
}

static int perform_io(size_t nbyte, uintptr_t vaddr, open_file *file,
                      void *callback, uint8_t op, void *buff) {
    size_t bytes_left = nbyte;
    int offset = vaddr & (PAGE_SIZE_4K - 1);

    while (bytes_left > 0) {
        int len = bytes_left > (PAGE_SIZE_4K - offset) ? (PAGE_SIZE_4K - offset) : bytes_left;

        if (!vaddr_check(vaddr)) {
            return -1;
        }

        sync_bin_sem_wait(data_sem);
        char *data = (char *)frame_data(get_frame(vaddr));
        nfs_args args = {len, data + offset, nfs_sem};
        if (op & READ_IO) {
            args.err = file->file_read(file->handle, data + offset, len, callback, &args);
        } else if (op & WRITE_IO) {
            args.err = file->file_write(file->handle, data + offset, len, callback, &args);
        }
        sync_bin_sem_post(data_sem);

        if (args.err < 0) {
            return -1;
        } else if (!args.err) {
            break;
        } else if (args.err != len) {
            bytes_left -= args.err;
            break;
        }

        sync_bin_sem_wait(data_sem);
        if (op & DATA_TO_BUFF) {
            memcpy(buff + (nbyte - len), data + offset, len);
        } else if (op & BUFF_TO_DATA) {
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

void syscall_sos_open(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    /* Wait for the nfs to be mounted before continuing with open. */
    extern sync_bin_sem_t *nfs_open_sem;
    sync_bin_sem_wait(nfs_open_sem);
    sync_bin_sem_post(nfs_open_sem);

    ZF_LOGE("syscall: thread example made syscall %d!\n", SYSCALL_SOS_OPEN);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    seL4_Word vaddr = curr_task->msg[1];
    int path_len = curr_task->msg[2];
    int mode = curr_task->msg[3];
    if ((mode != O_WRONLY) && (mode != O_RDONLY) && (mode != O_RDWR)) {
        seL4_SetMR(0, -1);
        return;
    }

    char *file_path = calloc(path_len, sizeof(char));
    int res = perform_io(path_len, vaddr, NULL, NULL, DATA_TO_BUFF, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }

    open_file *file;
    if (!strcmp(file_path, "console")) {
        sync_bin_sem_wait(file_sem);
        if (console_open_for_read && mode != O_WRONLY) {
            sync_bin_sem_post(file_sem);
            seL4_SetMR(0, -1);
            return;
        } else if (mode != O_WRONLY) {
            console_open_for_read = true;
        }
        sync_bin_sem_post(file_sem);
        file = file_create(file_path, mode, network_console_send, deque);
    } else {
        nfs_args args = {.sem = nfs_sem};
        if (nfs_open_file(file_path, mode, nfs_async_open_cb, &args) < 0) {
            seL4_SetMR(0, -1);
            return;
        }
        file = file_create(file_path, mode, nfs_write_file, nfs_read_file);
        file->handle = args.buff;
    }

    uint32_t fd;
    int err = fdt_put(user_process.fdt, file, &fd);
    seL4_SetMR(0, err ? -1 : (int) fd);
}

void syscall_sos_close(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_CLOSE);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    sync_bin_sem_wait(file_sem);
    open_file *found = fdt_get_file(user_process.fdt, curr_task->msg[1]);
    sync_bin_sem_post(file_sem);
    if (found == NULL) {
        seL4_SetMR(0, -1);
        return;
    } else if (!strcmp(found->path, "console") && found->mode != O_WRONLY) {
        sync_bin_sem_wait(file_sem);
        console_open_for_read = false;
        sync_bin_sem_post(file_sem);
    } else {
        nfs_args args = {.sem = nfs_sem};
        if (nfs_close_file(found->handle, nfs_async_close_cb, &args) < 0) {
            seL4_SetMR(0, -1);
            return;
        }

        if (args.err) {
            seL4_SetMR(0, -1);
            return;
        }
    }
    fdt_remove(user_process.fdt, curr_task->msg[1]);
    seL4_SetMR(0, 0);
}

void syscall_sos_read(seL4_MessageInfo_t *reply_msg, struct task *curr_task) 
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_READ);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Receive a fd from sos.c */
    int read_fd = curr_task->msg[1];
    seL4_Word vaddr = curr_task->msg[2];
    int nbyte = curr_task->msg[3];

    sync_bin_sem_wait(file_sem);
    open_file *found = fdt_get_file(user_process.fdt, read_fd);
    sync_bin_sem_post(file_sem);
    if (found == NULL || found->mode == O_WRONLY) {
        /* Set the reply message to be an error value */
        seL4_SetMR(0, -1);
        return;
    }

    int res = perform_io(nbyte, vaddr, found, nfs_async_read_cb, READ_IO, NULL);
    seL4_SetMR(0, res);
}

void syscall_sos_write(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_WRITE);
    /* Construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    /* Receive fd, virtual address, and number of bytes from sos.c */
    int write_fd = curr_task->msg[1];
    seL4_Word vaddr = curr_task->msg[2];
    size_t nbyte = curr_task->msg[3];

    /* Find the file associated with the file descriptor */
    sync_bin_sem_wait(file_sem);
    open_file *found = fdt_get_file(user_process.fdt, write_fd);
    sync_bin_sem_post(file_sem);
    if (found == NULL || found->mode == O_RDONLY) {
        /* Set the reply message to be an error value and return early */
        seL4_SetMR(0, -1);
        return;
    }
    int res = perform_io(nbyte, vaddr, found, nfs_async_write_cb, WRITE_IO, NULL);
    seL4_SetMR(0, res);
}

void syscall_sos_usleep(bool *have_reply, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_USLEEP);
    register_timer(curr_task->msg[1], wakeup, (void *) curr_task);
    *have_reply = false;
}

void syscall_sos_time_stamp(seL4_MessageInfo_t *reply_msg)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_TIME_STAMP);
    /* construct a reply message of length 1 */
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    /* Set the reply message to be the timestamp since booting in microseconds */
    seL4_SetMR(0, timestamp_us(timestamp_get_freq()));
}

void syscall_sys_brk(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SYS_BRK);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);

    uintptr_t newbrk = curr_task->msg[1];
    if (newbrk <= 0) {
        seL4_SetMR(0, PROCESS_HEAP_START);        
    } else if (newbrk >= ALIGN_DOWN(user_process.stack_reg->base, PAGE_SIZE_4K)) {
        seL4_SetMR(0, 0);
    } else {
        user_process.heap_reg->size = newbrk - PROCESS_HEAP_START;
        seL4_SetMR(0, newbrk);
    }
}

void syscall_sos_stat(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_STAT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    seL4_Word path_vaddr = curr_task->msg[1];
    seL4_Word buf_vaddr = curr_task->msg[2];
    size_t path_len = curr_task->msg[3];

    /* Perform stat operation. We don't assume it's only on 1 page */
    char *file_path = calloc(path_len, sizeof(char));
    int res = perform_io(path_len, path_vaddr, NULL, NULL, DATA_TO_BUFF, file_path);
    if (res == -1) {
        seL4_SetMR(0, -1);
        return;
    }

    sos_stat_t stat = {ST_SPECIAL, 0, 0, 0, 0};
    if (strcmp(file_path, "console")) {
        nfs_args args = {0, &stat, nfs_sem};
        if (nfs_stat_file(file_path, nfs_async_stat_cb, &args)) {
            seL4_SetMR(0, -1);
            return;
        }
        if (args.err < 0) {
            seL4_SetMR(0, -1);
            return;
        }
        stat.st_fmode = (stat.st_fmode & ~0100000) >> 6;
    }
    
    res = perform_io(sizeof(sos_stat_t), buf_vaddr, NULL, NULL, BUFF_TO_DATA, &stat);
    seL4_SetMR(0, res < 0 ? res : 0);
}

void syscall_sos_getdirent(seL4_MessageInfo_t *reply_msg, struct task *curr_task)
{
    ZF_LOGE("syscall: some thread made syscall %d!\n", SYSCALL_SOS_GETDIRENT);
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    int pos = curr_task->msg[1];
    seL4_Word vaddr = curr_task->msg[2];
    size_t nbyte = curr_task->msg[3];

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
    if (!strcmp(nfsdirent->name, "..") || !strcmp(nfsdirent->name, ".")) {
        seL4_SetMR(0, -2);
        return;
    } else if (i + 1 == pos && nfsdirent->next == NULL) {
        seL4_SetMR(0, 0);
        return;
    } else if (i < pos && nfsdirent->next == NULL) {
        seL4_SetMR(0, -1);
        return;
    }

    size_t path_len = strlen(nfsdirent->name);
    size_t size = nbyte < path_len ? nbyte : path_len;
    int res = perform_io(size, vaddr, NULL, NULL, BUFF_TO_DATA, nfsdirent->name);

    seL4_Word new_vaddr = vaddr + size;
    unsigned char *data = frame_data(get_frame(new_vaddr));
    data[new_vaddr & (PAGE_SIZE_4K - 1)] = 0;
    nfs_close_dir(args.buff);
    
    seL4_SetMR(0, res);
}

void syscall_unknown_syscall(seL4_MessageInfo_t *reply_msg, seL4_Word syscall_number)
{
    *reply_msg = seL4_MessageInfo_new(0, 0, 0, 1);
    ZF_LOGE("System call %lu not implemented\n", syscall_number);
    /* Reply -1 to an unimplemented syscall */
    seL4_SetMR(0, -1);
}

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
}