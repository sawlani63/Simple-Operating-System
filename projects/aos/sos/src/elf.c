/*
 * Copyright 2019, Data61
 * Commonwealth Scientific and Industrial Research Organisation (CSIRO)
 * ABN 41 687 119 230.
 *
 * This software may be distributed and modified according to the terms of
 * the GNU General Public License version 2. Note that NO WARRANTY is provided.
 * See "LICENSE_GPLv2.txt" for details.
 *
 * @TAG(DATA61_GPL)
 */
#include <utils/util.h>
#include <stdbool.h>
#include <sel4/sel4.h>
#include <elf/elf.h>
#include <string.h>
#include <assert.h>
#include <cspace/cspace.h>

#include "frame_table.h"
#include "ut.h"
#include "mapping.h"
#include "elfload.h"
#include "nfs.h"

extern seL4_CPtr nfs_signal;

/*
 * Convert ELF permissions into seL4 permissions.
 */
static inline seL4_CapRights_t get_sel4_rights_from_elf(unsigned long permissions)
{
    bool canRead = permissions & PF_R || permissions & PF_X;
    bool canWrite = permissions & PF_W;

    if (!canRead && !canWrite) {
        return seL4_AllRights;
    }

    return seL4_CapRights_new(false, false, canRead, canWrite);
}

/*
 * Load an elf segment into the given vspace.
 *
 *
 * The content to load is either zeros or the content of the ELF
 * file itself, or both.
 * The split between file content and zeros is as follows.
 *
 * File content: [dst, dst + file_size)
 * Zeros:        [dst + file_size, dst + segment_size)
 *
 * Note: if file_size == segment_size, there is no zero-filled region.
 * Note: if file_size == 0, the whole segment is just zero filled.
 *
 * @param cspace        of the loader, to allocate slots with
 * @param loader        vspace of the loader
 * @param loadee        vspace to load the segment in to
 * @param src           pointer to the content to load
 * @param segment_size  size of segment to load
 * @param file_size     end of section that should be zero'd
 * @param dst           destination base virtual address to load
 * @param permissions   for the mappings in this segment
 * @return
 *
 */
static int load_segment_into_vspace(cspace_t *cspace, seL4_CPtr loadee, const char *src, size_t segment_size,
                                    size_t file_size, uintptr_t dst, seL4_Word flags, addrspace_t *as, unsigned *size, pid_t pid)
{
    assert(file_size <= segment_size);

    /* We work a page at a time in the destination vspace. */
    unsigned int pos = 0;
    seL4_Error err = seL4_NoError;
    while (pos < segment_size) {
        uintptr_t loadee_vaddr = (ROUND_DOWN(dst, PAGE_SIZE_4K));

        /* allocate the frame for the loadees address space */
        frame_ref_t frame = clock_alloc_frame(loadee_vaddr, pid, 1, 0);
        if (frame == NULL_FRAME) {
            ZF_LOGD("Failed to alloc frame");
            return -1;
        }

        /* map the frame into the loadee address space */
        err = sos_map_frame(cspace, loadee, loadee_vaddr, flags, frame, as);
        (*size)++;

        /* A frame has already been mapped at this address. This occurs when segments overlap in
         * the same frame, which is permitted by the standard. That's fine as we
         * leave all the frames mapped in, and this one is already mapped. Give back
         * the ut we allocated and continue on to do the write.
         *
         * Note that while the standard permits segments to overlap, this should not occur if the segments
         * have different permissions - you should check this and return an error if this case is detected. */
        bool already_mapped = (err == seL4_DeleteFirst);

        if (already_mapped) {
            free_frame(frame);
        } else if (err != seL4_NoError) {
            ZF_LOGE("Failed to map into loadee at %p, error %u", (void *) loadee_vaddr, err);
            free_frame(frame);
            return -1;
        }

        /* finally copy the data */
        unsigned char *loader_data = frame_data(frame);

        /* Write any zeroes at the start of the block. */
        size_t leading_zeroes = dst % PAGE_SIZE_4K;
        memset(loader_data, 0, leading_zeroes);
        loader_data += leading_zeroes;

        /* Copy the data from the source. */
        size_t segment_bytes = PAGE_SIZE_4K - leading_zeroes;
        if (pos < file_size) {
            size_t file_bytes = MIN(segment_bytes, file_size - pos);
            memcpy(loader_data, src, file_bytes);
            loader_data += file_bytes;
            
            /* Fill in the end of the frame with zereos */
            size_t trailing_zeroes = PAGE_SIZE_4K - (leading_zeroes + file_bytes);
            memset(loader_data, 0, trailing_zeroes);
        } else {
            memset(loader_data, 0, segment_bytes);
        }

        /* Unpin the frame */
        unpin_frame(frame);

        dst += segment_bytes;
        pos += segment_bytes;
        src += segment_bytes;
    }
    return 0;
}

int elf_load(cspace_t *cspace, elf_t *elf_file, open_file *file, addrspace_t *as, seL4_CPtr vspace, unsigned *size, pid_t pid)
{
    int num_headers = elf_getNumProgramHeaders(elf_file);
    for (int i = 0; i < num_headers; i++) {

        /* Skip non-loadable segments (such as debugging data). */
        if (elf_getProgramHeaderType(elf_file, i) != PT_LOAD) {
            continue;
        }

        /* Fetch information about this segment. */
        size_t offset = elf_getProgramHeaderOffset(elf_file, i);
        size_t file_size = elf_getProgramHeaderFileSize(elf_file, i);
        size_t segment_size = elf_getProgramHeaderMemorySize(elf_file, i);
        uintptr_t vaddr = elf_getProgramHeaderVaddr(elf_file, i);
        seL4_Word flags = elf_getProgramHeaderFlags(elf_file, i);

        /* Load the segment into the address space */
        seL4_Word reg_flags = ((flags & 1) << 2) | (flags & 2) | ((flags & 4) >> 2);
        insert_region(as, vaddr, segment_size, reg_flags);

        char *src = malloc(sizeof(char) * file_size);
        io_args args = {.signal_cap = nfs_signal, .buff = src};
        int err = nfs_pread_file(pid, file, NULL, offset, file_size, nfs_pagefile_read_cb, &args);
        if (err < (int) file_size) {
            free(src);
            ZF_LOGE("NFS: Error in reading ELF segment");
            return 1;
        }
        /* Wait for the callback to finish */
        seL4_Wait(nfs_signal, 0);
        if (args.err < 0) {
            free(src);
            return 1;
        }

        /* Copy it across into the vspace. */
        ZF_LOGD(" * Loading segment %p-->%p\n", (void *) vaddr, (void *)(vaddr + segment_size));
        err = load_segment_into_vspace(cspace, vspace, src, segment_size, file_size, vaddr,
                                           reg_flags, as, size, pid);
        if (err < 0) {
            ZF_LOGE("Elf loading failed!");
            return 1;
        }
        free(src);
    }
    return 0;
}

char *elf_load_header(open_file *file, unsigned long *elf_size)
{
    /**
     * Open the elf file on nfs and read the first 4096 bytes which includes the ELF and program headers.
     * Don't close the file here on nfs since we will need it opened to load segments into our vspace.
     */
    io_args args = {.signal_cap = nfs_signal};
    int error = nfs_open_file(file, nfs_async_open_cb, &args);
    if (error) {
        ZF_LOGE("NFS: Error in opening app");
        file_destroy(file);
        return NULL;
    }
    file->handle = args.buff;

    char *data = malloc(sizeof(char) * PAGE_SIZE_4K);
    args.buff = data;
    error = nfs_pread_file(0, file, NULL, 0, PAGE_SIZE_4K, nfs_pagefile_read_cb, &args);
    if (error < (int) PAGE_SIZE_4K) {
        ZF_LOGE("NFS: Error in reading ELF and program headers");
        free(data);
        file_destroy(file);
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        free(data);
        file_destroy(file);
        return NULL;
    }

    Elf64_Ehdr *header = (void *) data;
    *elf_size = header->e_shoff + (header->e_shentsize * header->e_shnum);
    return data;
}
