#include "console.h"

typedef int fmode_t;

struct file {
    int fd;
    fmode_t mode;
    int (*write_handler)(char *data, int len);
    char (*read_handler)(void);
    char* path;
    struct file *next;
};

struct file *file_stack = NULL;
int id = 1;

static struct file *create_file(fmode_t mode, int (*write_handler)(char *data, int len), char (*read_handler)(void), char* path) {
    struct file *new_file = malloc(sizeof(struct file));
    new_file->fd = id++;
    new_file->mode = mode;
    new_file->write_handler = write_handler;
    new_file->read_handler = read_handler;
    new_file->path = path;
    new_file->next = NULL;
    return new_file;
}

static void push_file(struct file *file) {
    file->next = file_stack;
    file_stack = file;
}

int push_new_file(fmode_t mode, int (*write_handler)(char *data, int len), char (*read_handler)(void), char* path) {
    struct file *file = create_file(mode, write_handler, read_handler, path);
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

struct file *pop_file(int fd) {
    struct file *curr = file_stack;
    if (curr == NULL) {
        return NULL;
    } else if (file_stack->fd == fd) {
        file_stack = file_stack->next;
        return curr;
    }

    while (curr->next != NULL) {
        if (curr->next->fd == fd) {
            struct file *ret = curr->next;
            curr->next = curr->next->next;
            return ret;
        }
        curr = curr->next;
    }
    return NULL;
}