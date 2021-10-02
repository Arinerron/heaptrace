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

#include "debugger.h"


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

    start_debugger(chargv);
    return 0;
}
