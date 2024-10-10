#include <stdlib.h>
#include <sync/bin_sem.h>

sync_bin_sem_t *queue_sem = NULL;
seL4_CPtr sem_cptr;

struct node {
    char c;
    struct node *next;
};

struct node *read_queue = NULL;

void enqueue(__attribute__((__unused__)) struct network_console *network_console, char c) {
    struct node *new_node = malloc(sizeof(struct node));
    if (new_node == NULL) {
        ZF_LOGF_IF(!new_node, "No memory for new console node object");
        return;
    }
    new_node->c = c;
    new_node->next = NULL;

    if (read_queue == NULL) {
        read_queue = new_node;
    } else {
        struct node *curr = read_queue;
        while (curr->next != NULL) {
            curr = curr->next;
        }
        curr->next = new_node;
    }
    sync_bin_sem_post(queue_sem);
}

int deque(UNUSED void *handle, uint64_t count, UNUSED void *cb, void *args) {
    /* We don't use a callback here so we'll just use the args to the callback
     * as the buffer we will be writing to. */
    char *buff = (char *) args;
    for (uint64_t i = 0; i < count; i++) {
        sync_bin_sem_wait(queue_sem);
        buff[i] = read_queue->c;
        struct node *next = read_queue->next;
        free(read_queue);
        read_queue = next;
        if (buff[i] == '\n') {
            return i + 1;
        }
    }
    return count;
}

void init_console_sem() {
    queue_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!queue_sem, "No memory for new semaphore object");
    ut_t *sem_ut = alloc_retype(&sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(queue_sem, sem_cptr, 0);
}