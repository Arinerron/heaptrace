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

#include "breakpoint.h"
#include "symbol.h"
#include "proc.h"

#define MAX_PATH_SIZE 1024 // WARNING: if you change this, search for 1024 first to avoid buffer overflow. I hardcoded it in some places because idk how to concat const int to str conveniently lol

#define STATUS_SIGSEGV 0xb7f

extern int OPT_FOLLOW_FORK;

extern int CHILD_PID;
extern uint64_t CHILD_LIBC_BASE;

static int should_map_syms;

void _check_breakpoints(int pid, ProcMapsEntry *pme_head);

static uint64_t _calc_offset(int pid, SymbolEntry *se, ProcMapsEntry *pme_head);
void evaluate_funcid(Breakpoint **bps, int bpsc, char *fname, ProcMapsEntry *pme_head);


void end_debugger(int pid, int status);
void start_debugger(char *chargv[]);
