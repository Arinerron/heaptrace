#define _GNU_SOURCE
#include <sys/syscall.h>
#include <inttypes.h>
#include <string.h>
#include <sys/personality.h>
#include <linux/auxvec.h>
#include <signal.h>
#include <string.h>

#include "debugger.h"
#include "handlers.h"
#include "heap.h"
#include "logging.h"
#include "breakpoint.h"
#include "options.h"
#include "funcid.h"
#include "proc.h"

int CHILD_PID = 0;
static int in_breakpoint = 0;

void _check_breakpoints(int pid, ProcMapsEntry *pme_head) {
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
                        ASSERT(0, "nargs is only supported up to 3 args; ignoring bp pre_handler. Please report this!");
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
                                uint64_t val_at_reg_rsp = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, regs.rsp, 0L);
                                if (OPT_VERBOSE) {
                                    ProcMapsEntry *pme = pme_find_addr(pme_head, val_at_reg_rsp);
                                    if (pme) {
                                        ret_ptr_section_type = pme->pet;
                                    }
                                }

                                // install return value catcher breakpoint
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


static uint64_t _calc_offset(int pid, SymbolEntry *se, ProcMapsEntry *pme_head) {
    ProcMapsEntry *bin_pme = pme_walk(pme_head, PROCELF_TYPE_BINARY);
    ASSERT(bin_pme, "Target binary is missing from process mappings (!bin_pme in _calc_offset). Please report this!");

    if (se->type == SE_TYPE_STATIC) {
        return bin_pme->base + se->offset;
    } else if (se->type == SE_TYPE_DYNAMIC || se->type == SE_TYPE_DYNAMIC_PLT) {
        ProcMapsEntry *libc_pme = pme_walk(pme_head, PROCELF_TYPE_LIBC);
        if (!libc_pme) return 0;

        uint64_t got_ptr = bin_pme->base + se->offset;
        uint64_t got_val = ptrace(PTRACE_PEEKDATA, pid, got_ptr, NULL);
        debug(". peeked val=%p at GOT ptr=%p for %s (type=%d)\n", got_val, got_ptr, se->name, se->type);

        // check if this is in the PLT or if it's resolved to libc
        if (se->type == SE_TYPE_DYNAMIC_PLT && (got_val >= bin_pme->base && got_val < bin_pme->end)) {
            // I had issues where GOT contained the address + 0x6, see  https://github.com/Arinerron/heaptrace/issues/22#issuecomment-937420315
            // see https://www.intezer.com/blog/malware-analysis/executable-linkable-format-101-part-4-dynamic-linking/ for explanation why it's like that
            got_val -= (uint64_t)0x6;
        }

        return got_val;
    }

    return 0;
}


// attempts to identify functions in stripped ELFs (bin_pme->base only, not libc)
void evaluate_funcid(Breakpoint **bps, int bpsc, char *fname, ProcMapsEntry *pme_head) {
    ProcMapsEntry *bin_pme = pme_walk(pme_head, PROCELF_TYPE_BINARY);
    ASSERT(bin_pme, "Target binary does not exist in process mappings (!bin_pme in evaluate_funcid). Please report this!");

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
            uint64_t ptr = bin_pme->base + sig->offset;
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
    int _was_sigsegv = 0;
    log(COLOR_LOG "\n================================= " COLOR_LOG_BOLD "END HEAPTRACE" COLOR_LOG " ================================\n" COLOR_RESET);
    int code = (status >> 8) & 0xffff;

    if ((status == STATUS_SIGSEGV) || status == 0x67f || (WIFSIGNALED(status) && !WIFEXITED(status))) { // some other abnormal code
        log(COLOR_ERROR "Process exited with signal " COLOR_ERROR_BOLD "SIG%s" COLOR_ERROR " (" COLOR_ERROR_BOLD "%d" COLOR_ERROR ")", sigabbrev_np(code), code);
        if (BETWEEN_PRE_AND_POST) log(" while executing " COLOR_ERROR_BOLD "%s" COLOR_ERROR " (" SYM COLOR_ERROR ")", BETWEEN_PRE_AND_POST, get_oid());
        log("." COLOR_RESET " ", code);
        _was_sigsegv = 1;
    }

    if (WCOREDUMP(status)) {
        log(COLOR_ERROR "Core dumped. " COLOR_LOG);
    }

    log("\n");
    show_stats();

    if (_was_sigsegv) check_should_break(1, BREAK_SIGSEGV, 0);
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
    should_map_syms = 1;
    check_should_break(1, BREAK_MAIN, 0);
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
        ProcMapsEntry *pme_head;

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

                ASSERT(at_entry, "unable to locate at_entry auxiliary vector. Please report this.");
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
                free_pme_list(pme_head);
                pme_head = 0;
                end_debugger(child, status);
            } else if (status == 0x57f) { /* status SIGTRAP */ } else {
                debug("warning: hit unknown status code %d\n", status);
            }

            _check_breakpoints(child, pme_head);
            if (should_map_syms) {
                should_map_syms = 0;

                // parse /proc/pid/maps
                pme_head = build_pme_list(child);
                ProcMapsEntry *bin_pme = pme_walk(pme_head, PROCELF_TYPE_BINARY);
                ProcMapsEntry *libc_pme = pme_walk(pme_head, PROCELF_TYPE_LIBC);
                
                // quick debug info about addresses/paths we found
                ASSERT(bin_pme, "Failed to find target binary in process mapping (!bin_pme). Please report this!");
                debug("Found memory maps... binary (%s): %p-%p", bin_pme->name, bin_pme->base, bin_pme->end);
                if (libc_pme) {
                    char *name = libc_pme->name;
                    if (!name) name = "<UNKNOWN>";
                    debug2(", libc (%s): %p-%p", libc_pme->name, libc_pme->base, libc_pme->end);
                }
                debug2("\n");

                // print the type of binary etc
                if (is_dynamic) {
                    verbose(COLOR_RESET_BOLD "Dynamically-linked");
                    if (is_stripped) verbose(", stripped");
                    verbose(" binary")

                    if (libc_pme && libc_pme->name) {
                        char *ptr = get_libc_version(libc_pme->name);
                        char *libc_version = ptr;
                        if (!ptr) libc_version = "???";
                        verbose(" using glibc version %s (%s)\n" COLOR_RESET, libc_version, libc_pme->name);
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

                // now that we know the base addresses, calculate offsets
                bp_malloc->addr = _calc_offset(child, se_malloc, pme_head);
                bp_calloc->addr = _calc_offset(child, se_calloc, pme_head);
                bp_free->addr = _calc_offset(child, se_free, pme_head);
                bp_realloc->addr = _calc_offset(child, se_realloc, pme_head);
                bp_reallocarray->addr = _calc_offset(child, se_reallocarray, pme_head);
                
                // prep breakpoint arrays
                Breakpoint *bps[] = {bp_malloc, bp_calloc, bp_free, bp_realloc, bp_reallocarray};
                int bpsc = 5;

                // final attempts to get symbol information (funcid + parse --symbol)
                if (is_stripped) evaluate_funcid(bps, bpsc, chargv[0], pme_head);
                evaluate_symbol_defs(bps, bpsc, pme_head);
                verbose("\n");

                // install breakpoints
                _add_breakpoint(child, bp_malloc);
                _add_breakpoint(child, bp_calloc);
                _add_breakpoint(child, bp_free);
                _add_breakpoint(child, bp_reallocarray);
            }

            ptrace(PTRACE_CONT, child, 0L, 0L);
        }

        free_pme_list(pme_head);
        pme_head = 0;
        warn("while loop exited. Please report this. Status: %d, exit status: %d\n", status, WEXITSTATUS(status));
    }
}
