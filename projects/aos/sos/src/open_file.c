#include "open_file.h"
#include "ut.h"
#include "utils.h"

open_file *file_create(string path, int mode, execute_io file_write, execute_io file_read) {
    if (path == NULL || file_write == NULL || file_read == NULL) {
        return NULL;
    }
    open_file *file = malloc(sizeof(open_file));
    if (file == NULL) {
        return NULL;
    }
    file->handle = NULL;
    file->mode = mode;
    file->path = path;
    file->file_read = file_read;
    file->file_write = file_write;
    file->offset = 0;
    file->size = 0;
    memset(file->cache_blocks, 0, LEVEL_SIZE * sizeof(uint8_t *));
    
    return file;
}

void file_destroy(open_file *file) {
    /* Since the path address was provided to us by the user, we assume
     * either they explicitly free it, or it will be freed when the page
     * table gets cleared / swapped to disk. */
    free(file);
}

static inline bool is_l3_empty(uint8_t *level) {
    for (uint8_t i = 0; i < LEVEL_SIZE; i++) {
        if (level[i] != 0) {
            return false;
        }
    }
    return true;
}

static inline bool is_l2_empty(uint8_t **level) {
    for (uint8_t i = 0; i < LEVEL_SIZE; i++) {
        if (level[i] != 0) {
            return false;
        }
    }
    return true;
}

int mark_block_dirty(open_file *file, uint32_t cache_block) {
    uint8_t l1_index = (cache_block >> 13) & MASK(5);
    uint8_t l2_index = (cache_block >> 8) & MASK(5);
    uint8_t l3_index = (cache_block >> 3) & MASK(5);
    uint8_t l3_offset = cache_block & MASK(3);
    
    if (file->cache_blocks[l1_index] == NULL) {
        file->cache_blocks[l1_index] = calloc(LEVEL_SIZE, sizeof(uint8_t *));
        if (file->cache_blocks[l1_index] == NULL) {
            printf("calloc failed allocating 2nd level bitmap\n");
            return -1;
        }
    }

    if (file->cache_blocks[l1_index][l2_index] == NULL) {
        file->cache_blocks[l1_index][l2_index] = calloc(LEVEL_SIZE, sizeof(uint8_t));
        if (file->cache_blocks[l1_index][l2_index] == NULL) {
            printf("calloc failed allocating 3rd level bitmap\n");
            return -1;
        }
    }

    file->cache_blocks[l1_index][l2_index][l3_index] |= (1U << l3_offset);
    return 0;
}

int mark_block_clean(open_file *file, uint32_t cache_block) {
    uint8_t l1_index = (cache_block >> 13) & MASK(5);
    uint8_t l2_index = (cache_block >> 8) & MASK(5);
    uint8_t l3_index = (cache_block >> 3) & MASK(5);
    uint8_t l3_offset = cache_block & MASK(3);

    if (file->cache_blocks[l1_index] == NULL || file->cache_blocks[l1_index][l2_index] == NULL) {
        return -1;
    }

    uint8_t bottom_entry = file->cache_blocks[l1_index][l2_index][l3_index] &= ~(1U << l3_offset);

    if (!bottom_entry && is_l3_empty(file->cache_blocks[l1_index][l2_index])) {
        free(file->cache_blocks[l1_index][l2_index]);
        file->cache_blocks[l1_index][l2_index] = NULL;

        if (is_l2_empty(file->cache_blocks[l1_index])) {
            free(file->cache_blocks[l1_index]);
            file->cache_blocks[l1_index] = NULL;
        }
    }
    return 0;
}

void cleanup_bitmap(open_file *file) {
    for (int l1 = 0; l1 < LEVEL_SIZE; l1++) {
        if (file->cache_blocks[l1] != NULL) {
            for (int l2 = 0; l2 < LEVEL_SIZE; l2++) {
                free(file->cache_blocks[l1][l2]);
            }
            free(file->cache_blocks[l1]);
        }
    }
    memset(file->cache_blocks, 0, LEVEL_SIZE * sizeof(uint8_t *));
}