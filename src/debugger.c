#include "debugger.h"
#include "handlers.h"

void bp_malloc_pre_handler(uint64_t size) {
    printf("... malloc(size=%x)\n", size);    
}


void bp_malloc_post_handler(uint64_t retval) {
    printf("\t-> %p\n", retval);
}


void bp_free_pre_handler(uint64_t ptr) {}


void bp_free_post_handler(uint64_t retval) {}


void bp_calloc_pre_handler(uint64_t nmemb, uint64_t size) {}


void bp_calloc_post_handler(uint64_t retval) {}


void bp_realloc_pre_handler(uint64_t ptr, uint64_t size) {}


void bp_realloc_post_handler(uint64_t retval) {}


void _check_breakpoints(int pid) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    uint64_t reg_rip = (uint64_t)regs.rip - 1;

    int _was_bp = 0;

    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        Breakpoint *bp = breakpoints[i];
        if (bp) {
            if (bp->addr == reg_rip) { // hit the breakpoint
                _was_bp = 1;
                //printf("Hit breakpoint %s (0x%x)\n", bp->name, reg_rip);
                ptrace(PTRACE_POKEDATA, pid, reg_rip, (uint64_t)bp->orig_data);

                // move rip back by one
                regs.rip = reg_rip; // NOTE: this is actually $rip-1
                ptrace(PTRACE_SETREGS, pid, 0L, &regs);
                
                if (!bp->_is_inside && bp->pre_handler) {
                    int nargs = bp->pre_handler_nargs;
                    if (nargs == 0) {
                        ((void(*)(void))bp->pre_handler)();
                    } else if (nargs == 1) {
                        ((void(*)(uint64_t))bp->pre_handler)(regs.rdi);
                    } else if (nargs == 2) {
                        ((void(*)(uint64_t, uint64_t))bp->pre_handler)(regs.rdi, regs.rsi);
                    } else if (nargs == 3) {
                        ((void(*)(uint64_t, uint64_t, uint64_t))bp->pre_handler)(regs.rdi, regs.rsi, regs.rdx);
                    } else {
                        printf("warning: nargs is only supported up to 3 args; ignoring bp pre_handler\n");
                    }
                }
                
                // reset breakpoint and continue
                ptrace(PTRACE_SINGLESTEP, pid, 0L, 0L);
                wait(0L);

                if (!bp->_is_inside) {
                    if (!bp->_bp) { // this is a regular breakpoint
                        bp->_is_inside = 1;

                        // install return value catcher breakpoint
                        uint64_t val_at_reg_rsp = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, regs.rsp, 0L);
                        Breakpoint *bp2 = (Breakpoint *)malloc(sizeof(struct Breakpoint));
                        bp2->name = "_tmp";
                        bp2->addr = val_at_reg_rsp;
                        bp2->pre_handler = 0;
                        bp2->post_handler = 0;
                        _add_breakpoint(pid, bp2);
                        bp2->_bp = bp;

                        // reinstall original breakpoint
                        ptrace(PTRACE_POKEDATA, pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                    } else { // this is a return value catcher breakpoint
                        Breakpoint *orig_bp = bp->_bp;
                        if (orig_bp->post_handler) {
                            ((void(*)(uint64_t))orig_bp->post_handler)(regs.rax);
                        }
                        _remove_breakpoint(pid, bp);
                        orig_bp->_is_inside = 0;
                    }
                } else {
                    // reinstall original breakpoint
                    ptrace(PTRACE_POKEDATA, pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                }

                //printf("BREAKPOINT peeked 0x%x at breakpoint 0x%x\n", ptrace(PTRACE_PEEKDATA, pid, reg_rip, 0L), reg_rip);

            }
        }
    }
}


uint64_t get_binary_base(int pid) {
    // get the full path to the binary
    char *exepath = malloc(MAX_PATH_SIZE + 1);
    char *fname = malloc(MAX_PATH_SIZE + 1);
    snprintf(exepath, MAX_PATH_SIZE, "/proc/%d/exe", pid);
    int nbytes = readlink(exepath, fname, MAX_PATH_SIZE);
    fname[nbytes] = '\x00';
    free(exepath);

    // get the path to the /proc/pid/maps file
    char *mapspath = malloc(MAX_PATH_SIZE + 1);
    snprintf(mapspath, MAX_PATH_SIZE, "/proc/%d/maps", pid);
    //printf("maps path: %s\n", mapspath);

    FILE *f = fopen(mapspath, "r");
    
    uint64_t binary_base;
    while (1) {
        uint64_t cur_binary_base = 0;
        int _tmp[9]; // sorry I'm a terible programmer

        if (fscanf(f, "%llx-%x", &cur_binary_base, &_tmp) == EOF) { // 7f738fb9f000-7f738fba0000
            break;
        }

        fscanf(f, " ");
        fscanf(f, "%c%c%c%c", &_tmp, &_tmp, &_tmp, &_tmp); // rw-p
        fscanf(f, " ");
        fscanf(f, "%8c", &_tmp); // 000a9000
        fscanf(f, " ");
        fscanf(f, "%d:%d", &_tmp, &_tmp); // 103:08
        fscanf(f, " ");
        fscanf(f, "%d", &_tmp); // 18615725
        fscanf(f, " ");

        char *cur_fname = malloc(MAX_PATH_SIZE + 1);
        memset(cur_fname, 0, sizeof cur_fname);
        fscanf(f, "%1024s\n", cur_fname); // XXX: sometimes reads in the next line. Usually works.
        // XXX: technically a filename can contain a newline

        //printf("current filename: \"%s\" (v.s. \"%s\")\n", cur_fname, fname);
        if (strcmp(fname, cur_fname) == 0) {
            //printf("Found it!\n");
            // XXX: technically, the first entry is not necessarily the base. But ALMOST ALWAYS is. You'd need a very specific configuration to break this.
            binary_base = cur_binary_base;
            free(cur_fname);
            break;
        }

        free(cur_fname);
    }

    fclose(f);
    free(mapspath);
    return binary_base;
}


uint64_t get_libc_base(int pid) {
    // TODO: get the full path to the libc
    char *fname = "/usr/lib/libc-2.33.so";

    // get the path to the /proc/pid/maps file
    char *mapspath = malloc(MAX_PATH_SIZE + 1);
    snprintf(mapspath, MAX_PATH_SIZE, "/proc/%d/maps", pid);
    //printf("maps path: %s\n", mapspath);

    FILE *f = fopen(mapspath, "r");
    
    uint64_t binary_base;
    while (1) { // TODO: standardize this code!!!
        uint64_t cur_binary_base = 0;
        int _tmp[9]; // sorry I'm a terible programmer

        if (fscanf(f, "%llx-%s ", &cur_binary_base, &_tmp) == EOF) { // 7f738fb9f000-7f738fba0000
            break;
        }
        printf("asdf: %s\n", _tmp);

        fscanf(f, "%s ", &_tmp); // rw-p
        fscanf(f, "%s ", &_tmp); // 000a9000
        fscanf(f, "%s:%s ", &_tmp, &_tmp); // 103:08
        fscanf(f, "%d", &_tmp); // 18615725
        printf("num: %d\n",  *_tmp);
        if(*_tmp != 0) {
        fscanf(f, " ");

        char *cur_fname = malloc(MAX_PATH_SIZE + 1);
        memset(cur_fname, 0, sizeof cur_fname);
        fscanf(f, "%1024s\n", cur_fname); // XXX: sometimes reads in the next line. Usually works.
        // XXX: technically a filename can contain a newline

        printf("current filename: \"%s\" (v.s. \"%s\")\n", cur_fname, fname);
        if (strcmp(fname, cur_fname) == 0) {
            printf("Found it!\n");
            // XXX: technically, the first entry is not necessarily the base. But ALMOST ALWAYS is. You'd need a very specific configuration to break this.
            binary_base = cur_binary_base;
            free(cur_fname);
            break;
        }

        free(cur_fname);} else {
            fscanf(f, "%s\n", &_tmp);
        }
    }

    fclose(f);
    free(mapspath);
    return binary_base;
}


static uint64_t _calc_offset(int pid, SymbolEntry *se) { // TODO: cleanup
    if (se->type == SE_TYPE_STATIC) {
        uint64_t bin_base = get_binary_base(pid);
        return bin_base + se->offset;
    } else if (se->type == SE_TYPE_DYNAMIC) {
        uint64_t bin_base = get_libc_base(pid);
        printf("using libc base %p\n", bin_base);
        return bin_base + se->offset;
    }

    return 0;
}


void start_debugger(char *chargv[]) {
    SymbolEntry *se_malloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_malloc->name = "malloc";
    Breakpoint *bp_malloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_malloc->name = "malloc";
    bp_malloc->pre_handler = pre_malloc;
    bp_malloc->pre_handler_nargs = 1;
    bp_malloc->post_handler = post_malloc;

    SymbolEntry *se_calloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_calloc->name = "calloc";
    Breakpoint *bp_calloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_calloc->name = "calloc";
    bp_calloc->pre_handler = bp_calloc_pre_handler;
    bp_calloc->pre_handler_nargs = 2;

    SymbolEntry *se_free = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_free->name = "free";
    Breakpoint *bp_free = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_free->name = "free";
    bp_free->pre_handler = bp_free_pre_handler;
    bp_free->pre_handler_nargs = 1;

    SymbolEntry *se_realloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_realloc->name = "realloc";
    Breakpoint *bp_realloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_realloc->name = "realloc";
    bp_realloc->pre_handler = bp_realloc_pre_handler;
    bp_realloc->pre_handler_nargs = 2;

    SymbolEntry *ses[4] = {se_malloc, se_calloc, se_free, se_realloc};
    lookup_symbols(chargv[0], ses, 4);

    // ptrace section

    int child = fork();
    if (!child) {
        //printf("Starting process %s\n", chargv[0]);
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (execvp(chargv[0], chargv) == -1) {
            printf("Failed to execvp(\"%s\", ...): (%d) %s\n", chargv[0], errno, strerror(errno)); // XXX: not thread safe
            exit(1);
        }
    } else {
        int status;
        int first_signal = 1;

        /*wait(NULL);
        ptrace(PTRACE_CONT, child, 0L, 0L);*/
        //printf("Parent process\n");
        while(waitpid(child, &status, 0) && !WIFEXITED(status)) {
            //printf("... paused process. Signal: %p\n", status);
            if (first_signal) {
                first_signal = 0;
                //printf("Child binary base: %p\n", bin_base);

                bp_malloc->addr = _calc_offset(child, se_malloc);
                bp_calloc->addr = _calc_offset(child, se_calloc);
                bp_free->addr = _calc_offset(child, se_free);
                bp_realloc->addr = _calc_offset(child, se_realloc);

                // install breakpoints
                _add_breakpoint(child, bp_malloc);
                _add_breakpoint(child, bp_calloc);
                _add_breakpoint(child, bp_free);
                _add_breakpoint(child, bp_realloc);

                for (int i = 0; i < 4; i++) {
                    //uint64_t vaddr = bin_base + ses[i]->offset;
                    // XXX/TODO: fix PIE
                }
            } else {
                _check_breakpoints(child);
            }

            /*exit(0);

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, NULL, &regs);
            ptrace(PTRACE_SYSCALL, child, NULL, NULL);*/

            ptrace(PTRACE_CONT, child, 0L, 0L);
        }
        printf("While loop exited. Status: %d, exit status: %d\n", status, WEXITSTATUS(status));
    }
}
