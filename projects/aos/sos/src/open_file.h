#include <stdlib.h>

typedef const char * string;

typedef struct file {
    string path;
    int mode;
    void *nfsfh;
} open_file;

/**
 * Allocate memory and return a pointer to a new open file.
 * @param path A string containing the path to the file.
 * @param mode The permissions of the file (O_RDONLY, O_WRONLY, O_RDWR).
 * @return The value of the file open file.
 */
open_file *file_create(string path, int mode);

/**
 * Deallocates memory for the given file.
 * @param file A reference to an open file to be deallocated.
 */
void file_destroy(open_file *file);

void nfsfh_init(open_file *file, void *nfsfh);
int file_is_console(open_file *file);