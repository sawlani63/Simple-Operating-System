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

char deque() {
    sync_bin_sem_wait(queue_sem);
    char ret = read_queue->c;
    struct node *next = read_queue->next;
    free(read_queue);
    read_queue = next;
    return ret;
}

void init_console_sem() {
    queue_sem = malloc(sizeof(sync_bin_sem_t));
    ut_t *sem_ut = alloc_retype(&sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!sem_ut, "No memory for notification");
    sync_bin_sem_init(queue_sem, sem_cptr, 0);
}