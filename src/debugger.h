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

#define MAX_PATH_SIZE 1024 // WARNING: if you change this, search for 1024 first to avoid buffer overflow. I hardcoded it in some places because idk how to concat const int to str conveniently lol

#define STATUS_SIGSEGV 0xb7f

extern int CHILD_PID;
extern uint64_t CHILD_LIBC_BASE;

static int should_map_syms;

uint64_t get_auxv_entry(int pid);
void _check_breakpoints(int pid);

int get_binary_location(int pid, uint64_t *bin_start, uint64_t *bin_end);
uint64_t get_libc_base(int pid, char **libc_path_out);

void end_debugger(int pid, int status);
void start_debugger(char *chargv[]);
