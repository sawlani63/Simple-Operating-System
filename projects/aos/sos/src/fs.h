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

typedef int fmode_t;

struct file {
    int fd;
    fmode_t mode;
    int (*write_handler)(char c);
    char (*read_handler)(void);
    struct file *next;
};

struct file *file_stack = NULL;
int id = 1;

static struct file *create_file(fmode_t mode, int (*write_handler)(char c), char (*read_handler)(void)) {
    struct file *new_file = malloc(sizeof(struct file));
    new_file->fd = id++;
    new_file->mode = mode;
    new_file->write_handler = write_handler;
    new_file->read_handler = read_handler;
    new_file->next = NULL;
    return new_file;
}

static void push_file(struct file *file) {
    file->next = file_stack;
    file_stack = file;
}

int push_new_file(fmode_t mode, int (*write_handler)(char c), char (*read_handler)(void)) {
    if (queue_sem == NULL) {
        queue_sem = malloc(sizeof(sync_bin_sem_t));
        ut_t *sem_ut = alloc_retype(&sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
        ZF_LOGF_IF(!sem_ut, "No memory for notification");
        sync_bin_sem_init(queue_sem, sem_cptr, 0);
    }
    if (id == 2) {
        id += 2;
    }
    struct file *file = create_file(mode, write_handler, read_handler);
    push_file(file);
    return file->fd;
}

struct file *find_file(int fd) {
    struct file *curr = file_stack;
    while (curr != NULL) {
        if (curr->fd == fd) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}

struct file *find_prev_file(int fd) {
    struct file *curr = file_stack;
    while (curr->next != NULL) {
        if (curr->next->fd == fd) {
            return curr;
        }
        curr = curr->next;
    }
    return NULL;
}