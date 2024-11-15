#include "thread_pool.h"

#include <sync/bin_sem.h>
#include "utils.h"
#include "threads.h"
#include <sync/condition_var.h>

struct {
    struct task tasks[THREAD_QUEUE_SIZE];
    int front;
    int rear;
    int size;
} queue = {.front = 0, .rear = 0, .size = 0};

seL4_CPtr tpool_sem_cptr;
sync_bin_sem_t *tpool_sem = NULL;

seL4_CPtr signal_cv_cptr;
sync_cv_t *signal_cv = NULL;

void submit_task(struct task task) {
    sync_bin_sem_wait(tpool_sem);
    if (queue.size == THREAD_QUEUE_SIZE) {
        printf("Tried to add to a full task queue!\n");
    }
    queue.tasks[queue.rear] = task;
    queue.rear = (queue.rear + 1) % THREAD_QUEUE_SIZE;
    queue.size++;
    sync_bin_sem_post(tpool_sem);
    sync_cv_signal(signal_cv);
}

static struct task dequeue_task() {
    if (queue.size == 0) {
        printf("Tried to remove from an empty task queue!\n");
    }
    struct task task = queue.tasks[queue.front];
    queue.front = (queue.front + 1) % THREAD_QUEUE_SIZE;
    queue.size--;
    return task;
}

void start_sos_worker_thread(void *arg) {
    void (*input_func)(void *args) = arg;
    while (1) {
        sync_bin_sem_wait(tpool_sem);
        while (queue.size == 0) {
            sync_cv_wait(tpool_sem, signal_cv);
        }
        
        struct task task = dequeue_task();
        sync_bin_sem_post(tpool_sem);
        input_func(&task);
    }
}

void initialise_thread_pool(void (*input_func)(void *arg)) {
    tpool_sem = malloc(sizeof(sync_bin_sem_t));
    ut_t *ut = alloc_retype(&tpool_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_bin_sem_init(tpool_sem, tpool_sem_cptr, 1);

    signal_cv = malloc(sizeof(sync_cv_t));
    ZF_LOGF_IF(!signal_cv, "No memory for new cv object");
    ut = alloc_retype(&signal_cv_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!ut, "No memory for notification");
    sync_cv_init(signal_cv, signal_cv_cptr);

    for (int i = 0; i < NUM_THREADS; i++) {
        spawn(start_sos_worker_thread, input_func, 0, true, "thread pool");
    }
}