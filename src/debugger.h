#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <elf.h>
#include <errno.h>

#include "symbol.h"
#include "breakpoint.h"

#define MAX_PATH_SIZE 1024 // WARNING: if you change this, search for 1024 first to avoid buffer overflow. I hardcoded it in some places because idk how to concat const int to str conveniently lol

#define STATUS_SIGSEGV 0xb7f

void _check_breakpoints(int pid);
uint64_t get_binary_base(int pid);
void end_debugger(int pid, int status);
void start_debugger(char *chargv[]);
