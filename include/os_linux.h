#ifndef OS_LINUX_H_
#define OS_LINUX_H_

#define _GNU_SOURCE

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/uio.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

void os_startup();
bool os_enum_start();
uint32_t os_enum_next(const char* name);
void os_enum_end();
bool os_process_begin(uint32_t pid);
uint64_t os_process_next(uint64_t* size);
uint32_t os_process_read(uint64_t addr, void* buffer, uint32_t size);
void os_process_end();

#endif
