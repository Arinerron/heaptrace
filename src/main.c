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

#include "logging.h"
#include "options.h"
#include "debugger.h"


// TODO: arg parsing
// https://github.com/Arinerron/heaptrace/blob/main/heaptrace.c#L148


int main(int argc, char *argv[]) {
    char *chargv[argc + 1];

    if (argc == 1) {
        printf("%s <binary> [args...]\n", argv[0]);
        exit(1);
    }

    for (int i = 1; i < argc; i++) {
        chargv[i - 1] = argv[i];
    }
    chargv[argc - 1] = 0;

    output_fd = stderr;
    log("%s================================ %s%s%s ===============================\n%s\n", COLOR_LOG, BOLD("BEGIN HEAPTRACE"), COLOR_RESET);
    // TODO: parse args

    start_debugger(chargv);
    return 0;
}
