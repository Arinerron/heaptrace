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

#include "main.h"
#include "logging.h"
#include "options.h"
#include "debugger.h"
#include "context.h"


uint OPT_ATTACH_PID = 0;
uint KEEP_RUNNING = 1;

HeaptraceContext *FIRST_CTX = 0;

// https://stackoverflow.com/a/2436368
void segfault_sigaction(int signal, siginfo_t *si, void *arg) {
    log("\n");
    fatal("heaptrace segfaulted. Please re-run with --debug and report this.\n");
    exit(1);
}

void catch_segfault() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);
    sa.sa_sigaction = segfault_sigaction;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, NULL);
}

void sigint_action(int _) {
    debug("Caught Ctrl+C, notifying children...\n");
    KEEP_RUNNING = 0;
    if (FIRST_CTX && FIRST_CTX->pid) {
        // we need to get out of waitpid()
        // this should also send signal to children
        info("\nCaught Ctrl+C, sending signal to child PID %d...\n", FIRST_CTX->pid);
        kill(FIRST_CTX->pid, SIGTRAP);
        debug("Debugger should end momentarily...\n");
    }
}


int main(int argc, char *argv[]) {
    output_fd = stderr;

    catch_segfault();
    signal(SIGINT, sigint_action);

    HeaptraceContext *ctx = alloc_ctx();
    FIRST_CTX = ctx;
    ASSERT(ctx, "alloc_ctx() returned NULL. Please report this.");

    char *chargv[argc + 1];
    int start_at = parse_args(argc, argv);

    if (!OPT_ATTACH_PID) {
        for (int i = start_at; i < argc; i++) {
            chargv[i - start_at] = argv[i];
        }
        chargv[argc - start_at] = NULL;

        ctx->target_path = chargv[0];
        ctx->target_argv = chargv;

        #ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        chmod(ctx->target_path, 511);
        #endif

        // TODO: refactor this into a check_target_access(ctx) function
        struct stat path_stat;
        if (access(ctx->target_path, F_OK) != 0) {
            fatal("unable to execute \"%s\": file does not exist.\n", ctx->target_path);
            log(COLOR_WARN "hint: are you sure you specified the full path to the executable?\n" COLOR_RESET);
            exit(1);
        } else if (access(ctx->target_path, R_OK) != 0) {
            fatal("permission to read target \"%s\" denied.\n", ctx->target_path);
            log(COLOR_WARN "hint: chmod +r %s\n" COLOR_RESET, ctx->target_path);
            exit(1);
        } else if (access(ctx->target_path, X_OK) != 0) {
            fatal("permission to execute target \"%s\" denied.\n", ctx->target_path);
            log(COLOR_WARN "hint: chmod +x %s\n" COLOR_RESET, ctx->target_path);
            exit(1);
        } else {
            stat(ctx->target_path, &path_stat);
            if (!S_ISREG(path_stat.st_mode)) {
                fatal("unable to execute \"%s\": target is not a regular file.\n", ctx->target_path);
                log(COLOR_WARN "hint: did you accidentally specify the path to a directory?\n" COLOR_RESET);
                exit(1);
            }
        }
    } else {
        char *target_argv[] = {NULL};
        ctx->target_path = NULL;
        ctx->target_argv = target_argv;
    }

    start_debugger(ctx);
    return 0;
}
