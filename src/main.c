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

    if (access(chargv[0], F_OK) != 0) {
        fatal("unable to execute \"%s\": file does not exist.\n", chargv[0]);
        log(COLOR_WARN "hint: are you sure you specified the correct filename?\n" COLOR_RESET);
        exit(1);
    } else if (access(chargv[0], R_OK) != 0) {
        fatal("permission to read \"%s\" denied.\n", chargv[0]);
        log(COLOR_WARN "hint: chmod +r %s\n" COLOR_RESET, chargv[0]);
        exit(1);
    } else if (access(chargv[0], X_OK) != 0) {
        fatal("permission to execute \"%s\" denied.\n", chargv[0]);
        log(COLOR_WARN "hint: chmod +x %s\n" COLOR_RESET, chargv[0]);
        exit(1);
    }

    log(COLOR_LOG "================================ " COLOR_LOG_BOLD "BEGIN HEAPTRACE" COLOR_LOG " ===============================\n" COLOR_RESET "\n");
    
    start_debugger(chargv);
    return 0;
}
