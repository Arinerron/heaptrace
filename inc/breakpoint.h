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

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

typedef struct Breakpoint {
    char *name;
    uint64_t addr;
    uint64_t orig_data;
    void *pre_handler;
    int pre_handler_nargs;
    void *post_handler;

    int _is_inside;
    void *_bp;
} Breakpoint;

#define BREAKPOINTS_COUNT 16
extern Breakpoint *breakpoints[BREAKPOINTS_COUNT];

void _add_breakpoint(int pid, Breakpoint *bp);
void _remove_breakpoint(int pid, Breakpoint *bp, int should_break);
void _remove_breakpoints(int pid, int should_break);

#endif
