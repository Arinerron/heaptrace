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

#include "context.h"
#include "breakpoint.h"
#include "symbol.h"
#include "proc.h"

#define MAX_PATH_SIZE 1024 // WARNING: if you change this, search for 1024 first to avoid buffer overflow. I hardcoded it in some places because idk how to concat const int to str conveniently lol

#define STATUS_SIGSEGV 0xb7f

extern int OPT_FOLLOW_FORK;

void _check_breakpoints(HeaptraceContext *ctx);

static uint64_t calculate_bp_offset(HeaptraceContext *ctx, Breakpoint *bp);
void evaluate_funcid(HeaptraceContext *ctx, Breakpoint **bps);


void end_debugger(HeaptraceContext *ctx, int should_detach);
void start_debugger(HeaptraceContext *ctx);
