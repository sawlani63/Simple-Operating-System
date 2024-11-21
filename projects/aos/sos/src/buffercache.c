#include "buffercache.h"
#include "frame_table.h"
#include "vmem_layout.h"
#include "network.h"
#include "nfs.h"
#include "utils.h"
#include "khash.h"

#include <sync/bin_sem.h>
#include <clock/clock.h>

#define CACHE_MAP_SIZE (1 << 18) // Half the total number of frames in the system (2^18)
#define MAX_READ_AHEAD 16

long prev_blocks[3] = {-1, -1, -1};
uint8_t num_blocks_reading = 1;

seL4_CPtr cache_ep;
seL4_CPtr cache_reply;

sync_bin_sem_t *cache_sem;
seL4_CPtr cache_sem_cptr;
extern sync_bin_sem_t *data_sem;

/* FNV-1a hash function */
static inline khint64_t hash_key(cache_key_t key) {
    const uint64_t fnv_prime = 1099511628211;
    uint64_t hash = 14695981039346656037ULL;
    
    hash = (hash ^ key.block_num) * fnv_prime;
    hash = (hash ^ (uint64_t)key.handle) * fnv_prime;

    return hash;
}

static inline int keys_equal(cache_key_t a, cache_key_t b) {
    return a.handle == b.handle && a.block_num == b.block_num;
}

KHASH_INIT(cache, cache_key_t, frame_ref_t, 1, hash_key, keys_equal)
khash_t(cache) *cache_map = NULL;

/* Initialise a buffer cache map.
 * This should take up 64KB (flags) + 4MB (keys) + 2MB (values) ≈ 6MB of space */
int buffercache_init() {
    cache_map = kh_init(cache);
    if (cache_map == NULL) {
        return 1;
    }

    alloc_retype(&cache_ep, seL4_EndpointObject, seL4_EndpointBits);
    ut_t *reply_ut = alloc_retype(&cache_reply, seL4_ReplyObject, seL4_ReplyBits);
    if (reply_ut == NULL) {
        ZF_LOGF("Failed to alloc reply object ut");
    }

    cache_sem = malloc(sizeof(sync_bin_sem_t));
    ZF_LOGF_IF(!cache_sem, "No memory for semaphore object");
    ut_t *data_ut = alloc_retype(&cache_sem_cptr, seL4_NotificationObject, seL4_NotificationBits);
    ZF_LOGF_IF(!data_ut, "No memory for notification");
    sync_bin_sem_init(cache_sem, cache_sem_cptr, 1);

    return kh_resize(cache, cache_map, CACHE_MAP_SIZE) < 0 ? 1 : 0;
}

static int buffercache_readahead(int pid, struct file *file, char *data, uint64_t offset, void *cb, void *args, cache_key_t key) {
    /* Shift previous blocks history. */
    prev_blocks[0] = prev_blocks[1];
    prev_blocks[1] = prev_blocks[2];
    prev_blocks[2] = key.block_num;

    /* Update the num_blocks_reading based on access pattern */
    if (prev_blocks[0] != -1 && 
        prev_blocks[1] == prev_blocks[0] + 1 && 
        prev_blocks[2] == prev_blocks[1] + 1) {
        num_blocks_reading = MIN(num_blocks_reading * 2, MAX_READ_AHEAD);
    } else if (prev_blocks[1] != prev_blocks[2] - 1) {
        num_blocks_reading = 1;
    }

    /* Allocate frames for read-ahead blocks and map them into the hash map. */
    frame_ref_t *refs = malloc(MAX_READ_AHEAD * sizeof(frame_ref_t));
    size_t frames_allocated = 0;
    for (uint8_t i = 0; i < num_blocks_reading; i++) {
        cache_key_t ahead_key = {.handle = key.handle, .block_num = key.block_num + i};
        
        /* Check for EOF. */
        if (ahead_key.block_num * NFS_BLKSIZE >= file->size) {
            break;
        }

        int err = 0;
        khiter_t iter = kh_put(cache, cache_map, ahead_key, &err);
        if (err == -1) {
            break;
        }

        refs[i] = clock_alloc_frame(0, pid, 1, 1);
        if (refs[i] == NULL_FRAME) {
            break;
        } else if (!err) {
            continue;
        }
        
        kh_value(cache_map, iter) = refs[i];
        frames_allocated++;

        /* Mark the frame allocated as dirty. */
        mark_block_dirty(file, iter);
    }

    /* Pass all the frames to nfs_pread_file at once, and have that read the data into the frames. */
    ((io_args *)args)->cache_frames = refs;
    ((io_args *)args)->num_frames = frames_allocated;
    ZF_LOGE("E %d %d", offset, file->size);
    return MIN(nfs_pread_file(0, file, data, ALIGN_DOWN(offset, NFS_BLKSIZE), frames_allocated * NFS_BLKSIZE, cb, args), NFS_BLKSIZE);
}

static int buffercache_writethrough(int pid, struct file *file, char *data, uint64_t offset, void *cb, void *args, cache_key_t key) {
    frame_ref_t ref = clock_alloc_frame(0, pid, 1, 1);
    if (ref == NULL_FRAME) {
        return -1;
    }
    int err;
    khiter_t iter = kh_put(cache, cache_map, key, &err);
    if (err == -1) {
        printf("Error adding to buffer cache map\n");
        return -1;
    }
    kh_value(cache_map, iter) = ref;

    ((io_args *) args)->cache_frames = &kh_value(cache_map, iter);
    mark_block_dirty(file, iter);
    return nfs_pread_file(0, file, data, ALIGN_DOWN(offset, NFS_BLKSIZE), NFS_BLKSIZE, cb, args);
}

int buffercache_write(int pid, struct file *file, char *data, uint64_t offset, uint64_t len, void *cb, void *args) {
    if (file->handle == NULL || len > NFS_BLKSIZE) {
        return -1;
    }

    uint64_t bytes_left = len;
    sync_bin_sem_wait(cache_sem);
    while (bytes_left > 0) {
        cache_key_t key = {.handle = file->handle, .block_num = offset / NFS_BLKSIZE};
        uint16_t blk_offset = offset - key.block_num * NFS_BLKSIZE;

        khiter_t iter = kh_get(cache, cache_map, key);
        frame_ref_t cache;
        sync_bin_sem_wait(data_sem);
        if (iter == kh_end(cache_map)) {
            sync_bin_sem_post(data_sem);
            if (bytes_left < NFS_BLKSIZE && offset < ALIGN_UP(file->size, NFS_BLKSIZE)) {
                int res = buffercache_writethrough(pid, file, data, offset, cb, args, key);
                sync_bin_sem_post(cache_sem);
                return res < (int)NFS_BLKSIZE ? -1 : (int)len;
            }
            int err;
            iter = kh_put(cache, cache_map, key, &err);
            if (err == -1) {
                printf("Error adding to buffer cache map\n");
                return -1;
            }
            cache = clock_alloc_frame(0, pid, 1, 1);
            kh_value(cache_map, iter) = cache;
        } else {
            cache = kh_value(cache_map, iter);
            pin_frame(cache);
        }

        uint16_t write_ammount = MIN(bytes_left, NFS_BLKSIZE - blk_offset);
        memcpy(frame_data(cache) + blk_offset, data, write_ammount);
        unpin_frame(cache);
        sync_bin_sem_post(data_sem);
        
        mark_block_dirty(file, iter);

        bytes_left -= write_ammount;
        offset += write_ammount;
        data += write_ammount;
    }

    ((io_args *) args)->cached = true;
    sync_bin_sem_post(cache_sem);
    return len;
}

int buffercache_read(int pid, struct file *file, char *data, uint64_t offset, uint64_t len, void *cb, void *args) {
    if (len > NFS_BLKSIZE || file->handle == NULL) {
        return -1; // error
    } else if (offset >= file->size) {
        ZF_LOGE("YUCKY B len %d offset %d file->size %d", len, offset, file->size); 
        return -2; // exit early
    }

    uint64_t bytes_left = len = MIN(len, file->size - offset);
    sync_bin_sem_wait(cache_sem);
    while (bytes_left > 0) {
        cache_key_t key = {.handle = file->handle, .block_num = offset / NFS_BLKSIZE};
        uint16_t blk_offset = offset - key.block_num * NFS_BLKSIZE;

        sync_bin_sem_wait(data_sem);
        khiter_t iter = kh_get(cache, cache_map, key);
        if (iter == kh_end(cache_map)) {
            sync_bin_sem_post(data_sem);
            ZF_LOGE("LEN %d", len);
            int res = buffercache_readahead(pid, file, data, offset, cb, args, key);
            sync_bin_sem_post(cache_sem);
            return res < (int)NFS_BLKSIZE ? -1 : (int)len;
        }
        frame_ref_t cache = kh_value(cache_map, iter);

        uint16_t read_amount = MIN(bytes_left, NFS_BLKSIZE - blk_offset);
        pin_frame(cache);
        memcpy(data, frame_data(cache) + blk_offset, read_amount);
        unpin_frame(cache);
        sync_bin_sem_post(data_sem);
        
        bytes_left -= read_amount;
        offset += read_amount;
        data += read_amount;
    }
    ((io_args *) args)->cached = true;
    sync_bin_sem_post(cache_sem);
    return len;
}

static inline int buffercache_flush_entry(open_file *file, cache_key_t key, frame_ref_t ref, uint64_t count) {
    io_args *args = malloc(sizeof(io_args));
    *args = (io_args){NFS_BLKSIZE, NULL, cache_ep, NULL, NULL, 0, false};
    int res = nfs_pwrite_file(0, file, (char *) frame_data(ref), key.block_num * NFS_BLKSIZE,
                              count, nfs_buffercache_flush_cb, args);
    if (res < (int)count) {
        free(args);
        return -1;
    }
    return (int)count;
}

static inline int cleanup_bitmap_and_pending_requests(open_file *file, int outstanding_requests) {
    cleanup_bitmap(file);
    bool failed = false;
    while (outstanding_requests > 0) {
        seL4_Recv(cache_ep, 0, cache_reply);
        int target = seL4_GetMR(0);
        int result = seL4_GetMR(1);
        
        if (target != result) {
            failed = true;
        }
        outstanding_requests--;
    }
    return failed ? -1 : 0;
}

int buffercache_clean_frame(cache_key_t key, frame_ref_t ref) {
    io_args *args = malloc(sizeof(io_args));
    *args = (io_args){NFS_BLKSIZE, NULL, cache_ep, NULL, NULL, 0, false};
    int res = nfs_pwrite_handle(key.handle, (char *) frame_data(ref), key.block_num * NFS_BLKSIZE,
                                NFS_BLKSIZE, nfs_buffercache_flush_cb, args);
    if (res < (int)NFS_BLKSIZE) {
        free(args);
        return -1;
    }
    seL4_Recv(cache_ep, 0, cache_reply);
    int target = seL4_GetMR(0);
    int result = seL4_GetMR(1);
    if (target != result) {
        return -1;
    }
    kh_del(cache, cache_map, kh_get(cache, cache_map, key));
    free_frame(ref);
    return 0;
}

int buffercache_flush(open_file *file) {
    #define MAX_BATCH_SIZE 3
    uint16_t outstanding_requests = 0;
    uint64_t bytes_left = file->size;

    for (uint32_t l1_index = 0; l1_index < LEVEL_SIZE; l1_index++) {
        if (file->cache_blocks[l1_index] == NULL) {
            continue;
        }

        for (uint16_t l2_index = 0; l2_index < LEVEL_SIZE; l2_index++) {
            if (file->cache_blocks[l1_index][l2_index] == NULL) {
                continue;
            }

            for (uint8_t l3_index = 0; l3_index < LEVEL_SIZE; l3_index++) {
                for (uint8_t bit = 0; bit < 8; bit++) {
                    if (file->cache_blocks[l1_index][l2_index][l3_index] & (1U << bit)) {
                        if (outstanding_requests >= MAX_BATCH_SIZE) {
                            while (outstanding_requests > 0) {
                                seL4_Recv(cache_ep, 0, cache_reply);
                                int target = seL4_GetMR(0);
                                int result = seL4_GetMR(1);
                                
                                if (target != result) {
                                    cleanup_bitmap_and_pending_requests(file, outstanding_requests);
                                    return -1;
                                }
                                
                                outstanding_requests--;
                            }
                        }
                        khiter_t iter = (l1_index << 13) | (l2_index << 8) | (l3_index << 3) | bit;
                        cache_key_t key = kh_key(cache_map, iter);
                        frame_ref_t ref = kh_value(cache_map, iter);
                        uint16_t write_amount = MIN(NFS_BLKSIZE, bytes_left);
                        int res = buffercache_flush_entry(file, key, ref, write_amount);
                        if (res < 0) {
                            return -1;
                        }
                        bytes_left -= write_amount;
                        outstanding_requests++;
                        if (bytes_left == 0) {
                            return cleanup_bitmap_and_pending_requests(file, outstanding_requests);
                        }
                    }
                }
                
            }
        }
    }

    return cleanup_bitmap_and_pending_requests(file, outstanding_requests);
}