#include <stdlib.h>
#include <stdint.h>

typedef const char * string;
typedef int (*rd_handler)(void *handle, uint64_t count, void *cb, void *args);
typedef int (*wr_handler)(void *handle, char *data, uint64_t len, void *callback, void *args);

typedef struct file {
    string path;
    int mode;
    wr_handler file_write;
    rd_handler file_read;
    void *handle; // i dont like this
} open_file;

/**
 * Allocate memory and return a pointer to a new open file.
 * @param path A string containing the path to the file.
 * @param mode The permissions of the file (O_RDONLY, O_WRONLY, O_RDWR).
 * @param file_write A function pointer used as the write callback.
 * @param file_read A function pointer used as the read callback.
 * @return The value of the file open file.
 */
open_file *file_create(string path, int mode, wr_handler file_write, rd_handler file_read);

/**
 * Deallocates memory for the given file.
 * @param file A reference to an open file to be deallocated.
 */
void file_destroy(open_file *file);

void nfsfh_init(open_file *file, void *nfsfh);