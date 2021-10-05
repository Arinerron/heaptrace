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


int main(int argc, char *argv[]) {
    output_fd = stderr;

    char *chargv[argc + 1];
    int start_at = parse_args(argc, argv);
    for (int i = start_at; i < argc; i++) {
        chargv[i - start_at] = argv[i];
    }
    chargv[argc - start_at] = 0;

    log("%s================================ %s%s%s ===============================\n%s\n", COLOR_LOG, BOLD("BEGIN HEAPTRACE"), COLOR_RESET);
    // TODO: parse args

    start_debugger(chargv);
    return 0;
}
