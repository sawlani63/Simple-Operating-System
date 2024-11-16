#pragma once

#include "open_file.h"

int dentry_init();

open_file *dentry_check(string path, int mode, execute_io file_write, execute_io file_read);

int dentry_write(open_file *file);

void dentry_mark_closed(open_file *file);