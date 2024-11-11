#include <elf/elf.h>

size_t elfc_getSectionOffset(Elf64_Ehdr const *header, size_t i) {
    size_t s_offset = header->e_ehsize + (header->e_phentsize * header->e_phnum);
    Elf64_Shdr const *s_header = header + s_offset;
    return s_header[i].sh_offset;
}

size_t elfc_getSectionSize(Elf64_Ehdr const *header, size_t i) {
    size_t s_offset = header->e_ehsize + (header->e_phentsize * header->e_phnum);
    Elf64_Shdr const *s_header = header + s_offset;
    return s_header[i].sh_size;
}

uint32_t elfc_getSectionType(Elf64_Ehdr const *header, size_t i) {
    size_t s_offset = header->e_ehsize + (header->e_phentsize * header->e_phnum);
    Elf64_Shdr const *s_header = header + s_offset;
    return s_header[i].sh_type;
}

size_t elfc_getSectionNameOffset(Elf64_Ehdr const *header, const char *str_table, size_t i) {
    size_t s_offset = header->e_ehsize + (header->e_phentsize * header->e_phnum);
    Elf64_Shdr const *s_header = header + s_offset;
    return  s_header[i].sh_name;
}

const void *elf_getSection(elf_t *elf, Elf64_Ehdr const *header, size_t i, open_file *file) {
    if (i == 0 || i >= header->e_shnum) {
        return NULL;
    }
    size_t section_offset = elfc_getSectionOffset(header, i);
    size_t section_size = elfc_getSectionSize(header, i);
    if (section_size == 0) {
        return NULL;
    }
    size_t section_end = section_offset + section_size;
    /* possible wraparound - check that section end is not before section start */
    if (section_end > elf->elfSize || section_end < section_offset) {
        return NULL;
    }

    char *section = malloc(sizeof(char) * section_size);

    io_args args = {.signal_cap = nfs_signal, .buff = data};
    int error = nfs_pread_file(file, NULL, section_offset, section_size, nfs_pagefile_read_cb, &args);
    if (error < (int) section_size) {
        ZF_LOGE("NFS: Error in reading ELF section");
        free(section);
        return NULL;
    }
    seL4_Wait(nfs_signal, 0);
    if (args.err < 0) {
        free(section);
        return NULL;
    }

    return section;
}

const char *elfc_getStringTable(elf_t *elf, Elf64_Ehdr const *header, size_t index, open_file *file) {
    const char *string_table = elfc_getSection(elf, header, index, file);
    if (string_table == NULL) {
        return NULL;
    }
    if (elfc_getSectionType(header, index) != SHT_STRTAB) {
        return NULL;
    }
    size_t size = elfc_getSectionSize(header, index);
    if (string_table[size - 1] != 0) {
        return NULL;
    }
    return string_table;
}

const char *elfc_getSectionName(elf_t *elf, Elf64_Ehdr const *header, open_file *file, size_t i) {
    size_t str_table_idx = header->e_shstrndx;
    const char *str_table = elfc_getStringTable(elf, header, str_table_idx, file);
    size_t offset = elfc_getSectionNameOffset(header, str_table, i);
    size_t size = elfc_getSectionSize(header, str_table_idx);

    if (str_table == NULL || offset > size) {
        return "<corrupted>";
    }

    return str_table + offset;
}

const void *elfc_NamedSection(elf_t *elf_file, open_file *file)
{
    Elf64_Ehdr const *header = elf_file->elfFile;
    size_t numSections = header->e_shnum;
    for (size_t i = 0; i < numSections; i++) {
        if (!strcmp("__vsyscall", elfc_getSectionName(elf_file, header, file, i))) {
            return elfc_getSection(elf_file, header, i, file);
        }
    }
    return NULL;
}