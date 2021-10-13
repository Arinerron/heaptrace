#define _GNU_SOURCE
#include <sys/syscall.h>
#include <inttypes.h>
#include <string.h>
#include <sys/personality.h>
#include <linux/auxvec.h>

#include "debugger.h"
#include "handlers.h"
#include "heap.h"
#include "logging.h"
#include "breakpoint.h"
#include "options.h"
#include "funcid.h"

int CHILD_PID = 0;
char *CHILD_LIBC_PATH = 0;
static int in_breakpoint = 0;

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
                
                if (!in_breakpoint && !bp->_is_inside && bp->pre_handler) {
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
                        ASSERT(0, "nargs is only supported up to 3 args; ignoring bp pre_handler. Please report this!\n");
                    }
                }
                
                // reset breakpoint and continue
                ptrace(PTRACE_SINGLESTEP, pid, 0L, 0L);
                wait(0L);

                if (!bp->_is_inside) {
                    if (!bp->_bp) { // this is a regular breakpoint
                        if (!in_breakpoint) {
                            in_breakpoint = 1;
                            bp->_is_inside = 1;

                            if (bp->post_handler) {
                                // install return value catcher breakpoint
                                uint64_t val_at_reg_rsp = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, regs.rsp, 0L);
                                Breakpoint *bp2 = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
                                bp2->name = "_tmp";
                                bp2->addr = val_at_reg_rsp;
                                bp2->pre_handler = 0;
                                bp2->post_handler = 0;
                                _add_breakpoint(pid, bp2);
                                bp2->_bp = bp;
                            } else {
                                // we don't need a return catcher, so no way to track being inside func
                                in_breakpoint = 0;
                            }
                        }

                        // reinstall original breakpoint
                        ptrace(PTRACE_POKEDATA, pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                    } else { // this is a return value catcher breakpoint
                        Breakpoint *orig_bp = bp->_bp;
                        if (orig_bp) {
                            if (orig_bp->post_handler) {
                                ((void(*)(uint64_t))orig_bp->post_handler)(regs.rax);
                            }
                            _remove_breakpoint(pid, bp);
                            orig_bp->_is_inside = 0;
                        } else {
                            // we never installed a return value catcher breakpoint!
                            bp->_is_inside = 0;
                        }
                        in_breakpoint = 0;
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


int get_binary_location(int pid, uint64_t *bin_start, uint64_t *bin_end) {
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
    
    uint64_t binary_base = 0;
    uint64_t binary_end = 0;
    while (1) {
        uint64_t cur_binary_base = 0;
        uint64_t cur_binary_end = 0;
        int _tmp[9]; // sorry I'm a terible programmer

        if (fscanf(f, "%llx-%llx", &cur_binary_base, &cur_binary_end) == EOF) { // 7f738fb9f000-7f738fba0000
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
            //debug("fname %s: binary_base: %llx, binary_end: %llx\n", fname, cur_binary_base, cur_binary_end);
            if (!binary_base || cur_binary_base < binary_base) {
                binary_base = cur_binary_base;
            }
            if (!binary_end || cur_binary_end > binary_end) {
                binary_end = cur_binary_end;
            }
        } else if (binary_base && binary_end) { // if we already resolved and are now past those entries
            free(cur_fname);
            break;
        }

        free(cur_fname);
    }

    *bin_start = binary_base;
    *bin_end = binary_end;

    fclose(f);
    free(mapspath);
    return binary_base && binary_end;
}


uint64_t get_libc_base(int pid, char **libc_path_out) {
    if (CHILD_LIBC_BASE) {
        return CHILD_LIBC_BASE;
    }

    // TODO: get the full path to the libc
    char *fname = "/usr/lib/libc-2.33.so";

    // get the path to the /proc/pid/maps file
    char *mapspath = malloc(MAX_PATH_SIZE + 1);
    snprintf(mapspath, MAX_PATH_SIZE, "/proc/%d/maps", pid);
    //printf("maps path: %s\n", mapspath);

    FILE *f = fopen(mapspath, "r");
    
    uint64_t binary_base = 0 ;
    char *cur_fname = malloc(MAX_PATH_SIZE + 1);
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

            memset(cur_fname, 0, sizeof cur_fname);
            fscanf(f, "%1024s\n", cur_fname); // XXX: sometimes reads in the next line. Usually works.
            // XXX: technically a filename can contain a newline

            //printf("current filename: \"%s\" (v.s. \"%s\")\n", cur_fname, fname);
            //if (strcmp(fname, cur_fname) == 0) {
            if (strstr(cur_fname, "libc-") || strstr(cur_fname, "libc.so")) { // quite a hack
                // XXX: technically, the first entry is not necessarily the base. But ALMOST ALWAYS is. You'd need a very specific configuration to break this.
                binary_base = cur_binary_base;
                *libc_path_out = strdup(cur_fname);
                break;
            }

        } else {
            fscanf(f, "\n");
        }
    }

    fclose(f);
    free(cur_fname);
    free(mapspath);
    return binary_base;
}


static uint64_t _calc_offset(int pid, SymbolEntry *se, uint64_t bin_base, uint64_t bin_end, uint64_t libc_base) { // TODO: cleanup
    if (se->type == SE_TYPE_STATIC) {
        return bin_base + se->offset;
    } else if (se->type == SE_TYPE_DYNAMIC || se->type == SE_TYPE_DYNAMIC_PLT) {
        uint64_t libc_base = get_libc_base(pid, &CHILD_LIBC_PATH);
        if (!libc_base) return 0;
        //printf("using libc base %p\n", libc_base);
        ////printf("bin base: %p, se offset: %p\n", bin_base, se->offset);
        uint64_t got_ptr = bin_base + se->offset;
        uint64_t got_val = ptrace(PTRACE_PEEKDATA, pid, got_ptr, NULL);

        debug(". peeked %p at GOT entry %p for %s (%d)\n", got_val, got_ptr, se->name, se->type);
        if (se->type == SE_TYPE_DYNAMIC_PLT && (got_val >= bin_base && got_val <= bin_end)) { // check if this is in the PLT or if it's resolved to libc
            got_val -= (uint64_t)0x6;
            // I had issues where GOT contained the address + 0x6, see  https://github.com/Arinerron/heaptrace/issues/22#issuecomment-937420315
            // see https://www.intezer.com/blog/malware-analysis/executable-linkable-format-101-part-4-dynamic-linking/ for explanation why it's like that
        }

        return got_val;
    }

    return 0;
}


uint64_t get_auxv_entry(int pid) {
    char *auxvpath = malloc(MAX_PATH_SIZE + 1);
    snprintf(auxvpath, MAX_PATH_SIZE, "/proc/%d/auxv", pid);
    FILE *f = fopen(auxvpath, "r");

    unsigned long at_type;
    unsigned long at_value;
    unsigned long retval = 0;
    while (1) {
        if (!fread(&at_type, sizeof at_type, 1, f)) break;
        if (!fread(&at_value, sizeof at_value, 1, f)) break;
        //debug("AT_ENTRY=%lu, at_type=%lu, at_value=%lu\n", AT_ENTRY, at_type, at_value);
        if (at_type == AT_ENTRY) {
            retval = at_value;
            break;
        }
    }

    fclose(f);
    free(auxvpath);
    return retval;
}


// attempts to identify functions in stripped ELFs (bin_base only, not libc)
void evaluate_funcid(Breakpoint **bps, int bpsc, char *fname, uint64_t libc_base, uint64_t bin_base) {
    int _printed_debug = 0;
    FILE *f = fopen(fname, "r");
    FunctionSignature *sigs = find_function_signatures(f);
    for (int i = 0; i < 5; i++) {
        FunctionSignature *sig = &sigs[i];
        //printf("(2) -> %s (%p) - %x (%p)\n", sig->name, sig, sig->offset, sig->offset);
        if (sig->offset) {
            if (!_printed_debug) {
                _printed_debug = 1;
                info("Attempting to identify function signatures in " COLOR_LOG_BOLD "%s" COLOR_LOG " (stripped)...\n", fname);
            }
            uint64_t ptr = bin_base + sig->offset;
            info(COLOR_LOG "* found " COLOR_LOG_BOLD "%s" COLOR_LOG " at " PTR ".\n" COLOR_RESET, sig->name, PTR_ARG(sig->offset));
            for (int j = 0; j < bpsc; j++) {
                Breakpoint *bp = bps[j];
                if (!strcmp(sig->name, bp->name)) {
                    bp->addr = ptr;
                }
            }
        }
    }

    if (_printed_debug) info("\n");
    if (sigs) free(sigs);
    fclose(f);
}


void end_debugger(int pid, int status) {
    log(COLOR_LOG "\n================================= " COLOR_LOG_BOLD "END HEAPTRACE" COLOR_LOG " ================================\n" COLOR_RESET);
    int code = (status >> 8) & 0xffff;

    if ((status == STATUS_SIGSEGV) || status == 0x67f || (WIFSIGNALED(status) && !WIFEXITED(status))) { // some other abnormal code
        log(COLOR_ERROR "Process exited abnormally (status: " COLOR_ERROR_BOLD "%d" COLOR_ERROR ")." COLOR_RESET " ", code);
    }

    if (WCOREDUMP(status)) {
        log(COLOR_ERROR "Core dumped. " COLOR_LOG);
    }

    show_stats();

    _remove_breakpoints(pid);
    exit(0);
}


char *get_libc_version(char *libc_path) {
    FILE *f = fopen(libc_path, "r");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *string = malloc(fsize + 1);
    fread(string, 1, fsize, f);
    fclose(f);
    string[fsize] = 0;

    char *_prefix = " version ";
    char *_version = memmem(string, fsize, _prefix, strlen(_prefix));
    if (!_version) return 0;
    _version += strlen(_prefix);
    char *_period = strstr(_version, ".\n");
    if (!_period) return 0;
    *_period = '\x00';

    char *version = strdup(_version);

    free(string);

    return version;
}


uint64_t CHILD_LIBC_BASE = 0;

// this is triggered by a breakpoint. The address to _start (entry) is stored 
// in auxv and fetched on the first run.
void _pre_entry() {
    uint64_t libc_base = get_libc_base(CHILD_PID, &CHILD_LIBC_PATH);
    if (libc_base) {
        debug("found libc_base in _pre_entry: %p\n", libc_base);
        CHILD_LIBC_BASE = libc_base;
    }

    should_map_syms = 1;
}


static int should_map_syms = 0;

void start_debugger(char *chargv[]) {
    SymbolEntry *se_malloc = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
    se_malloc->name = "malloc";
    Breakpoint *bp_malloc = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
    bp_malloc->name = "malloc";
    bp_malloc->pre_handler = pre_malloc;
    bp_malloc->pre_handler_nargs = 1;
    bp_malloc->post_handler = post_malloc;

    SymbolEntry *se_calloc = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
    se_calloc->name = "calloc";
    Breakpoint *bp_calloc = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
    bp_calloc->name = "calloc";
    bp_calloc->pre_handler = pre_calloc;
    bp_calloc->pre_handler_nargs = 2;
    bp_calloc->post_handler = post_calloc;

    SymbolEntry *se_free = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
    se_free->name = "free";
    Breakpoint *bp_free = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
    bp_free->name = "free";
    bp_free->pre_handler = pre_free;
    bp_free->pre_handler_nargs = 1;
    bp_free->post_handler = post_free;

    SymbolEntry *se_realloc = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
    se_realloc->name = "realloc";
    Breakpoint *bp_realloc = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
    bp_realloc->name = "realloc";
    bp_realloc->pre_handler = pre_realloc;
    bp_realloc->pre_handler_nargs = 2;
    bp_realloc->post_handler = post_realloc;

    SymbolEntry *se_reallocarray = (SymbolEntry *)calloc(1, sizeof(SymbolEntry));
    se_reallocarray->name = "reallocarray";
    Breakpoint *bp_reallocarray = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
    bp_reallocarray->name = "reallocarray";
    bp_reallocarray->pre_handler = pre_reallocarray;
    bp_reallocarray->pre_handler_nargs = 3;
    bp_reallocarray->post_handler = post_reallocarray;

    SymbolEntry *ses[] = {se_malloc, se_calloc, se_free, se_realloc, se_reallocarray};
    int sesc = 5; // TODO turn into null terminated
    char *interp_name;
    lookup_symbols(chargv[0], ses, sesc, &interp_name);

    if (interp_name) {
        //debug("Using interpreter \"%s\".\n", interp_name);
    }

    // ptrace section
    
    log(COLOR_LOG "================================ " COLOR_LOG_BOLD "BEGIN HEAPTRACE" COLOR_LOG " ===============================\n" COLOR_RESET);
    
    
    int show_banner = 0;
    int is_dynamic = (se_malloc->type == SE_TYPE_DYNAMIC || se_calloc->type == SE_TYPE_DYNAMIC || se_free->type == SE_TYPE_DYNAMIC || se_realloc->type == SE_TYPE_DYNAMIC || se_reallocarray->type == SE_TYPE_DYNAMIC) || (se_malloc->type == SE_TYPE_DYNAMIC_PLT || se_calloc->type == SE_TYPE_DYNAMIC_PLT || se_free->type == SE_TYPE_DYNAMIC_PLT || se_realloc->type == SE_TYPE_DYNAMIC_PLT || se_reallocarray->type == SE_TYPE_DYNAMIC_PLT); // XXX: find a better way to do this LOL
    int is_stripped = (se_malloc->type == SE_TYPE_UNRESOLVED && se_calloc->type == SE_TYPE_UNRESOLVED && se_free->type == SE_TYPE_UNRESOLVED && se_realloc->type == SE_TYPE_UNRESOLVED && se_reallocarray->type == SE_TYPE_UNRESOLVED);

    if (is_stripped && !strlen(symbol_defs_str)) {
        warn("Binary appears to be stripped or does not use the glibc heap; heaptrace was not able to resolve any symbols. Please specify symbols via the -s/--symbols argument. e.g.:\n\n      heaptrace --symbols 'malloc=libc+0x100,free=libc+0x200,realloc=bin+123' ./binary\n\nSee the help guide at https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary\n");
        show_banner = 1;
    }

    int look_for_brk = is_dynamic;

    assert(!is_dynamic || (is_dynamic && interp_name));
    if (interp_name) {
        //get_glibc_path(interp_name, chargv[0]);
    }

    if (show_banner) {
        log(COLOR_LOG "================================================================================\n" COLOR_RESET);
    }
    log("\n");

    free(interp_name);
    interp_name = 0;

    int child = fork();
    if (!child) {
        // disable ASLR
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            warn("failed to disable aslr for child\n");
        }

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        extern char **environ;
        if (execvpe(chargv[0], chargv, environ) == -1) {
            fatal("failed to start target via execvp(\"%s\", ...): (%d) %s\n", chargv[0], errno, strerror(errno)); // XXX: not thread safe
            exit(1);
        }
    } else {
        int status;
        //should_map_syms = !is_dynamic;
        should_map_syms = 0;
        int first_signal = 1; // XXX: this is confusing. refactor later.
        CHILD_PID = child;

        while(waitpid(child, &status, 0)) {
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child, 0, &regs);

            if (first_signal) {
                first_signal = 0;
                uint64_t at_entry = get_auxv_entry(child);

                ASSERT(at_entry, "unable to locate at_entry auxiliary vector. Please report this.\n");
                // temporary solution is to uncomment the should_map_syms = !is_dynamic
                // see blame for this commit, or see commit after commit 2394278.
                
                Breakpoint *bp_entry = (Breakpoint *)malloc(sizeof(struct Breakpoint));
                bp_entry->name = "_entry";
                bp_entry->addr = at_entry;
                bp_entry->pre_handler = _pre_entry;
                bp_entry->pre_handler_nargs = 0;
                bp_entry->post_handler = 0;
                _add_breakpoint(child, bp_entry);
            }

            if (WIFEXITED(status) || WIFSIGNALED(status) || status == STATUS_SIGSEGV || status == 0x67f) {
                end_debugger(child, status);
            } else if (status == 0x57f) { /* status SIGTRAP */ } else {
                debug("warning: hit unknown status code %d\n", status);
            }

            _check_breakpoints(child);
            if (should_map_syms) {
                should_map_syms = 0;
                
                // print the type of binary etc
                if (is_dynamic) {
                    verbose(COLOR_RESET_BOLD "Dynamically-linked");
                    if (is_stripped) verbose(", stripped");
                    verbose(" binary")

                    if (CHILD_LIBC_PATH) {
                        char *ptr = get_libc_version(CHILD_LIBC_PATH);
                        char *libc_version = ptr;
                        if (!ptr) libc_version = "???";
                        verbose(" using glibc version %s (%s)\n" COLOR_RESET, libc_version, CHILD_LIBC_PATH);
                        if (ptr) {
                            free(ptr);
                            ptr = 0;
                        }
                    } else { verbose("\n"); }
                } else {
                    verbose(COLOR_RESET_BOLD "Statically-linked");
                    if (is_stripped) verbose(", stripped");
                    verbose(" binary\n" COLOR_RESET);
                }

                uint64_t bin_base = 0;
                uint64_t bin_end = 0;
                get_binary_location(child, &bin_base, &bin_end);
                uint64_t libc_base = get_libc_base(child, &CHILD_LIBC_PATH);
                debug("Using bin_base: %p, libc_base: %p\n", bin_base, libc_base);

                bp_malloc->addr = _calc_offset(child, se_malloc, bin_base, bin_end, libc_base);
                bp_calloc->addr = _calc_offset(child, se_calloc, bin_base, bin_end, libc_base);
                bp_free->addr = _calc_offset(child, se_free, bin_base, bin_end, libc_base);
                bp_realloc->addr = _calc_offset(child, se_realloc, bin_base, bin_end, libc_base);
                bp_reallocarray->addr = _calc_offset(child, se_reallocarray, bin_base, bin_end, libc_base);
                
                Breakpoint *bps[] = {bp_malloc, bp_calloc, bp_free, bp_realloc, bp_reallocarray};
                int bpsc = 5;
                if (is_stripped) evaluate_funcid(bps, bpsc, chargv[0], libc_base, bin_base);
                evaluate_symbol_defs(bps, bpsc, libc_base, bin_base);
                verbose("\n");

                // install breakpoints
                _add_breakpoint(child, bp_malloc);
                _add_breakpoint(child, bp_calloc);
                _add_breakpoint(child, bp_free);
                _add_breakpoint(child, bp_reallocarray);
            }

            ptrace(PTRACE_CONT, child, 0L, 0L);
        }
        warn("while loop exited. Please report this. Status: %d, exit status: %d\n", status, WEXITSTATUS(status));
    }
}
