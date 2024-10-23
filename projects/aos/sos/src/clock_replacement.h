#pragma once

#include "sos_syscall.h"

void init_bitmap();

frame_ref_t clock_alloc_page(seL4_Word vaddr);

int clock_try_page_in(seL4_Word vaddr);