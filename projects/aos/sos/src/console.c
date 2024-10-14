#include "console.h"
#include "ut.h"
#include "utils.h"
#include <stdlib.h>
#include <sync/bin_sem.h>
#include <sync/condition_var.h>

#define QUEUE_SIZE 4096 // TODO: MAKE DYNAMIC?

struct {
    char chars[QUEUE_SIZE];
    int front;
    int rear;
    int size;
} read_queue = {.front = 0, .rear = 0, .size = 0};

seL4_CPtr queue_sem_cptr;
sync_bin_sem_t *queue_sem = NULL;

seL4_CPtr signal_cv_console_cptr;
sync_cv_t *signal_cv_console = NULL;

void enqueue(UNUSED struct network_console *network_console, char c) {
    sync_bin_sem_wait(queue_sem);
    if (read_queue.size == QUEUE_SIZE) {
        printf("Tried to add to a full console queue!\n");
    }
    read_queue.chars[read_queue.rear] = c;
    read_queue.rear = (read_queue.rear + 1) % QUEUE_SIZE;
    read_queue.size++;
    sync_bin_sem_post(queue_sem);
    sync_cv_signal(signal_cv_console);
}

int deque(UNUSED void *handle, UNUSED char *data, uint64_t count, UNUSED void *cb, void *args) {
    sync_bin_sem_wait(queue_sem);
    char *buff = (char *) ((nfs_args *) args)->buff;
    for (uint64_t i = 0; i < count; i++) {
        while (read_queue.size == 0) {
            sync_cv_wait(queue_sem, signal_cv_console);
        }
        char c = read_queue.chars[read_queue.front];
        read_queue.front = (read_queue.front + 1) % QUEUE_SIZE;
        read_queue.size--;
        buff[i] = c;
        if (buff[i] == '\n') {
            sync_bin_sem_post(queue_sem);
            return i + 1;
        }
    }
    sync_bin_sem_post(queue_sem);

    return count;
}

void init_console_sem() {
    queue_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!queue_sem, "No memory for new semaphore object");
    ut_t *ut = alloc_retype(&queue_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_bin_sem_init(queue_sem, queue_sem_cptr, 1);

    signal_cv_console = malloc(sizeof(sync_cv_t));
    ZF_LOGF_IF(!signal_cv_console, "No memory for new cv object");
    ut = alloc_retype(&signal_cv_console_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_cv_init(signal_cv_console, signal_cv_console_cptr);
}