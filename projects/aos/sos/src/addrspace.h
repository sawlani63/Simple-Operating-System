#include <cspace/cspace.h>

typedef struct _region {
    seL4_Word base;
    size_t size;
    unsigned int perms;
    struct _region *next;
} region_t;

struct addrspace {
    seL4_CPtr ****page_table;
    region_t *regions;
};