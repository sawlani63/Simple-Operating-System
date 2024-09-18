#include <stdint.h>
#include <stdlib.h>

#define INITIAL_CAPACITY 8
#define SHRINK_THRESHOLD 0.25

typedef struct {
    uint32_t *data;
    int size;
    int capacity;
} Stack;

Stack stack = {NULL, 0, INITIAL_CAPACITY};
uint32_t curr_id = 0;

int create_stack() {
    stack.data = (uint32_t *) malloc(stack.capacity * sizeof(uint32_t));
    return stack.data == NULL ? 1 : 0;
}

static int resize_stack(int new_capacity) {
    uint32_t *new_data = (uint32_t *) realloc(stack.data, new_capacity * sizeof(uint32_t));
    if (new_data == NULL) {
        return 1;
    }
    stack.data = new_data;
    stack.capacity = new_capacity;
    return 0;
}

int push(uint32_t id) {
    if (stack.size == stack.capacity && resize_stack(stack.capacity * 2)) {
        return 1;
    }
    stack.data[stack.size++] = id;
    return 0;
}

static uint32_t pop() {
    return stack.size == 0 || stack.size < stack.capacity * SHRINK_THRESHOLD
           && resize_stack(stack.capacity / 2) ? 0 : stack.data[--stack.size];
}

uint32_t new_id() {
    uint32_t id = pop();
    return id == 0 ? ++curr_id : id;
}

void free_stack() {
    free(stack.data);
}