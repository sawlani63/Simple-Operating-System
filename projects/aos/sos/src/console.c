#include "console.h"
#include "ut.h"
#include "utils.h"
#include <stdlib.h>
#include <sync/bin_sem.h>

/* CHANGE QUEUE_SEM TO COND VAR LATER */
sync_bin_sem_t *queue_sem = NULL;
seL4_CPtr queue_sem_cptr;

sync_bin_sem_t *sync_sem = NULL;
seL4_CPtr sync_sem_cptr;

struct node {
    char c;
    struct node *next;
};

struct node *read_queue = NULL;

void enqueue(UNUSED struct network_console *network_console, char c) {
    struct node *new_node = malloc(sizeof(struct node));
    if (new_node == NULL) {
        ZF_LOGF_IF(!new_node, "No memory for new console node object");
        return;
    }
    new_node->c = c;
    new_node->next = NULL;

    sync_bin_sem_wait(sync_sem);
    if (read_queue == NULL) {
        read_queue = new_node;
    } else {
        struct node *curr = read_queue;
        while (curr->next != NULL) {
            curr = curr->next;
        }
        curr->next = new_node;
    }
    sync_bin_sem_post(sync_sem);
    sync_bin_sem_post(queue_sem);
}

int deque(UNUSED void *handle, UNUSED char *data, uint64_t count, UNUSED void *cb, void *args) {
    /* We don't use a callback here so we'll just use the args to the callback
     * as the buffer we will be writing to. */
    char *buff = (char *) ((nfs_args *) args)->buff;
    for (uint64_t i = 0; i < count; i++) {
        sync_bin_sem_wait(queue_sem);
        sync_bin_sem_wait(sync_sem);
        buff[i] = read_queue->c;
        struct node *next = read_queue->next;
        free(read_queue);
        read_queue = next;
        sync_bin_sem_post(sync_sem);
        if (buff[i] == '\n') {
            return i + 1;
        }
    }
    return count;
}

void init_console_sem() {
    queue_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!queue_sem, "No memory for new semaphore object");
    ut_t *sem_ut = alloc_retype(&queue_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(queue_sem, queue_sem_cptr, 0);

    sync_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!sync_sem, "No memory for new semaphore object");
    sem_ut = alloc_retype(&sync_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(sync_sem, sync_sem_cptr, 1);
}