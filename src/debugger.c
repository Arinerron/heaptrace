#include <sys/syscall.h>
#include <inttypes.h>
#include <sys/personality.h>

#include "debugger.h"
#include "handlers.h"
#include "heap.h"
#include "logging.h"

int CHILD_PID = 0;

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
                        warn("nargs is only supported up to 3 args; ignoring bp pre_handler\n");
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
    
    uint64_t binary_base = 0 ;
    while (1) { // TODO: standardize this code!!!
        uint64_t cur_binary_base = 0;
        uint64_t _tmp[9]; // sorry I'm a terible programmer

        if (fscanf(f, "%llx-%x ", &cur_binary_base, &_tmp) == EOF) { // 7f738fb9f000-7f738fba0000
            break;
        }

        //printf("before: %p %p\n", cur_binary_base, *_tmp);

        fscanf(f, "%c%c%c%c", &_tmp, &_tmp, &_tmp, &_tmp); // rw-p
        fscanf(f, " ");
        fscanf(f, "%8c", &_tmp); // 000a9000
        fscanf(f, " ");
        fscanf(f, "%d:%d", &_tmp, &_tmp); // 103:08
        fscanf(f, " ");
        fscanf(f, "%" PRIu64, &_tmp); // 18615725

        if(*_tmp != 0) {
            fscanf(f, " ");

            char *cur_fname = malloc(MAX_PATH_SIZE + 1);
            memset(cur_fname, 0, sizeof cur_fname);
            fscanf(f, "%1024s\n", cur_fname); // XXX: sometimes reads in the next line. Usually works.
            // XXX: technically a filename can contain a newline

            //printf("current filename: \"%s\" (v.s. \"%s\")\n", cur_fname, fname);
            if (strcmp(fname, cur_fname) == 0) {
                // XXX: technically, the first entry is not necessarily the base. But ALMOST ALWAYS is. You'd need a very specific configuration to break this.
                binary_base = cur_binary_base;
                free(cur_fname);
                break;
            }

            free(cur_fname);
        } else {
            fscanf(f, "\n");
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
    } else if (se->type == SE_TYPE_DYNAMIC || se->type == SE_TYPE_DYNAMIC_PLT) {
        uint64_t libc_base = get_libc_base(pid);
        if (!libc_base) return 0;
        //printf("using libc base %p\n", libc_base);
        uint64_t bin_base = get_binary_base(pid);
        //printf("bin base: %p, se offset: %p\n", bin_base, se->offset);
        uint64_t got_ptr = bin_base + se->offset;
        uint64_t got_val = ptrace(PTRACE_PEEKDATA, pid, got_ptr, NULL);
        if (se->type == SE_TYPE_DYNAMIC_PLT) {
            got_val -= (uint64_t)0x6; // see https://github.com/Arinerron/heaptrace/issues/22#issuecomment-937420315
        }
        //printf("ptr %p val %p\n", got_ptr, got_val);
        return got_val;
    }

    return 0;
}


void end_debugger(int pid, int status) {
    log(COLOR_LOG "\n================================= " COLOR_LOG_BOLD "END HEAPTRACE" COLOR_LOG " ================================\n" COLOR_RESET);

    if ((status == STATUS_SIGSEGV) || (WIFSIGNALED(status) && !WIFEXITED(status))) { // some other abnormal code
        log(COLOR_ERROR "Process exited abnormally (status: " COLOR_ERROR_BOLD "%d" COLOR_ERROR ")." COLOR_RESET " ", WTERMSIG(status));
    }

    if (WCOREDUMP(status)) {
        log(COLOR_ERROR "Core dumped. " COLOR_LOG);
    }

    show_stats();

    _remove_breakpoints(pid);
    exit(0);
}


void start_debugger(char *chargv[]) {
    SymbolEntry *se_malloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_malloc->name = "malloc";
    Breakpoint *bp_malloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_malloc->name = "malloc";
    bp_malloc->pre_handler = pre_malloc;
    bp_malloc->pre_handler_nargs = 1;
    bp_malloc->post_handler = post_malloc;

    // TODO calloc
    SymbolEntry *se_calloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_calloc->name = "calloc";
    Breakpoint *bp_calloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_calloc->name = "calloc";

    SymbolEntry *se_free = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_free->name = "free";
    Breakpoint *bp_free = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_free->name = "free";
    bp_free->pre_handler = pre_free;
    bp_free->pre_handler_nargs = 1;
    bp_free->post_handler = post_free;

    SymbolEntry *se_realloc = (SymbolEntry *) malloc(sizeof(SymbolEntry));
    se_realloc->name = "realloc";
    Breakpoint *bp_realloc = (Breakpoint *)malloc(sizeof(struct Breakpoint));
    bp_realloc->name = "realloc";
    bp_realloc->pre_handler = pre_realloc;
    bp_realloc->pre_handler_nargs = 2;
    bp_realloc->post_handler = post_realloc;

    SymbolEntry *ses[4] = {se_malloc, se_calloc, se_free, se_realloc};
    char *interp_name;
    lookup_symbols(chargv[0], ses, 4, &interp_name);

    if (interp_name) {
        //debug("Using interpreter \"%s\".\n", interp_name);
    }

    // ptrace section
    
    int is_dynamic = (se_malloc->type == SE_TYPE_DYNAMIC || se_calloc->type == SE_TYPE_DYNAMIC || se_free->type == SE_TYPE_DYNAMIC || se_realloc->type == SE_TYPE_DYNAMIC) || (se_malloc->type == SE_TYPE_DYNAMIC_PLT || se_calloc->type == SE_TYPE_DYNAMIC_PLT || se_free->type == SE_TYPE_DYNAMIC_PLT || se_realloc->type == SE_TYPE_DYNAMIC_PLT); // XXX: find a better way to do this LOL
    int look_for_brk = is_dynamic;

    assert(!is_dynamic || (is_dynamic && interp_name));
    if (interp_name) {
        //get_glibc_path(interp_name, chargv[0]);
    }

    free(interp_name);
    interp_name = 0;

    int child = fork();
    if (!child) {
        //printf("Starting process %s\n", chargv[0]);
        
        // disable ASLR
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            warn("failed to disable aslr\n");
        }

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        if (execvp(chargv[0], chargv) == -1) {
            fatal("failed to execvp(\"%s\", ...): (%d) %s\n", chargv[0], errno, strerror(errno)); // XXX: not thread safe
            abort();
        }
    } else {
        int status;
        int first_signal = !is_dynamic;
        CHILD_PID = child;

        /*wait(NULL);
        ptrace(PTRACE_CONT, child, 0L, 0L);*/
        //printf("Parent process\n");
        while(waitpid(child, &status, 0)) {
            //printf("... paused process. Signal: %p\n", status); // TODO add debug func

            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, 0, &regs);

            if (look_for_brk && regs.orig_rax == SYS_brk) { // XXX: how can we KNOW this is a syscall?
                ptrace(PTRACE_SYSCALL, child, 0, 0);
                waitpid(child, &status, 0); // run till end of syscall
                uint64_t libc_base = get_libc_base(child);
                if (libc_base) {
                    first_signal = 1; // trigger _calc_offsets
                    look_for_brk = 0;
                }
                //goto continueptrace;
            }

            if (WIFEXITED(status) || WIFSIGNALED(status) || status == STATUS_SIGSEGV) {
                end_debugger(child, status);
            } else if (status == 0x57f) { // status SIGTRAP
                // nothing
            } else {
            }

            if (first_signal) {
                first_signal = 0;
                //printf("Child binary base: %p\n", bin_base);

                bp_malloc->addr = _calc_offset(child, se_malloc);
                bp_calloc->addr = _calc_offset(child, se_calloc);
                bp_free->addr = _calc_offset(child, se_free);
                bp_realloc->addr = _calc_offset(child, se_realloc);

                //printf("addr: %p\n", bp_malloc->addr);

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

continueptrace:
            if (look_for_brk) {
                ptrace(PTRACE_SYSCALL, child, 0, 0);
            } else {
                ptrace(PTRACE_CONT, child, 0L, 0L);
            }
        }
        printf("While loop exited. Status: %d, exit status: %d\n", status, WEXITSTATUS(status));
    }
}
