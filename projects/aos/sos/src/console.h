#pragma once

#include <networkconsole/networkconsole.h>
#include "nfs.h"

void enqueue(UNUSED struct network_console *network_console, char c);

int deque(UNUSED void *handle, UNUSED char *data, uint64_t count, UNUSED void *cb, void *args);

void init_console_sem();