#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <elf.h>
#include <errno.h>

#define BREAKPOINTS_COUNT 16
#include "context.h"

#ifndef BREAKPOINT_H
#define BREAKPOINT_H

#define BREAKPOINT_OPT_REMOVE 1
#define BREAKPOINT_OPT_UNREGISTER 2
#define BREAKPOINT_OPT_FREE 4
#define BREAKPOINT_OPTS_ALL (BREAKPOINT_OPT_REMOVE | BREAKPOINT_OPT_UNREGISTER | BREAKPOINT_OPT_FREE)

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

void install_breakpoint(HeaptraceContext *ctx, Breakpoint *bp);
void _remove_breakpoint(HeaptraceContext *ctx, Breakpoint *bp, int opts);
void _remove_breakpoints(HeaptraceContext *ctx, int opts);

#endif
