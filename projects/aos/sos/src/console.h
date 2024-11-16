#pragma once

#include <networkconsole/networkconsole.h>
#include "nfs.h"

void enqueue(UNUSED struct network_console *network_console, char c);

int deque(UNUSED int pid, UNUSED open_file *file, UNUSED char *data, UNUSED uint64_t offset, uint64_t count, UNUSED void *cb, void *args);

void init_console_sem();

void netcon_reply(void *args);