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
#include "main.h"

static int in_breakpoint = 0;

int OPT_FOLLOW_FORK = 0;

void _check_breakpoints(HeaptraceContext *ctx) {
    struct user_regs_struct regs;
    ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs);
    uint64_t reg_rip = (uint64_t)regs.rip - 1;

    int _was_bp = 0;

    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        Breakpoint *bp = ctx->breakpoints[i];
        if (bp) {
            if (bp->addr == reg_rip) { // hit the breakpoint
                _was_bp = 1;
                //printf("Hit breakpoint %s (0x%x)\n", bp->name, reg_rip);
                ptrace(PTRACE_POKEDATA, ctx->pid, reg_rip, (uint64_t)bp->orig_data);

                // move rip back by one
                regs.rip = reg_rip; // NOTE: this is actually $rip-1
                ptrace(PTRACE_SETREGS, ctx->pid, NULL, &regs);
                
                if (!in_breakpoint && !bp->_is_inside && bp->pre_handler) {
                    int nargs = bp->pre_handler_nargs;
                    if (nargs == 0) {
                        ((void(*)(HeaptraceContext *))bp->pre_handler)(ctx);
                    } else if (nargs == 1) {
                        ((void(*)(HeaptraceContext *, uint64_t))bp->pre_handler)(ctx, regs.rdi);
                    } else if (nargs == 2) {
                        ((void(*)(HeaptraceContext *, uint64_t, uint64_t))bp->pre_handler)(ctx, regs.rdi, regs.rsi);
                    } else if (nargs == 3) {
                        ((void(*)(HeaptraceContext *, uint64_t, uint64_t, uint64_t))bp->pre_handler)(ctx, regs.rdi, regs.rsi, regs.rdx);
                    } else {
                        ASSERT(0, "nargs is only supported up to 3 args; ignoring bp pre_handler. Please report this!");
                    }
                }
                
                // reset breakpoint and continue
                ptrace(PTRACE_SINGLESTEP, ctx->pid, NULL, NULL);
                wait(NULL);

                if (!bp->_is_inside) {
                    if (!bp->_bp) { // this is a regular breakpoint
                        if (!in_breakpoint) {
                            in_breakpoint = 1;
                            bp->_is_inside = 1;

                            if (bp->post_handler) {
                                uint64_t val_at_reg_rsp = (uint64_t)ptrace(PTRACE_PEEKDATA, ctx->pid, regs.rsp, NULL);
                                if (OPT_VERBOSE) {
                                    ProcMapsEntry *pme = pme_find_addr(ctx->pme_head, val_at_reg_rsp);
                                    if (pme) {
                                        ctx->ret_ptr_section_type = pme->pet;
                                    }
                                }

                                // install return value catcher breakpoint
                                Breakpoint *bp2 = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
                                bp2->name = "_tmp";
                                bp2->addr = val_at_reg_rsp;
                                bp2->pre_handler = 0;
                                bp2->post_handler = 0;
                                install_breakpoint(ctx, bp2);
                                bp2->_bp = bp;
                            } else {
                                // we don't need a return catcher, so no way to track being inside func
                                in_breakpoint = 0;
                            }
                        }

                        // reinstall original breakpoint
                        ptrace(PTRACE_POKEDATA, ctx->pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                    } else { // this is a return value catcher breakpoint
                        Breakpoint *orig_bp = bp->_bp;
                        if (orig_bp) {
                            if (orig_bp->post_handler) {
                                ((void(*)(HeaptraceContext *, uint64_t))orig_bp->post_handler)(ctx, regs.rax);
                            }
                            _remove_breakpoint(ctx, bp, BREAKPOINT_OPTS_ALL);
                            orig_bp->_is_inside = 0;
                        } else {
                            // we never installed a return value catcher breakpoint!
                            bp->_is_inside = 0;
                        }
                        in_breakpoint = 0;
                    }
                } else {
                    // reinstall original breakpoint
                    ptrace(PTRACE_POKEDATA, ctx->pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                }

                //printf("BREAKPOINT peeked 0x%x at breakpoint 0x%x\n", ptrace(PTRACE_PEEKDATA, pid, reg_rip, 0L), reg_rip);

            }
        }
    }
}


static uint calculate_bp_addrs(HeaptraceContext *ctx, Breakpoint **bps) {
    uint show_banner = 0;
    ProcMapsEntry *bin_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_BINARY);
    ASSERT(bin_pme, "calculate_bp_addrs: target binary is missing from process mappings (!bin_pme). Please report this!");

    // if glibc exists, lookup symbols
    ProcMapsEntry *libc_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_LIBC);
    if (libc_pme) {
        ctx->libc->path = libc_pme->name;

        // prefix all se_names with "__libc_"
        int i = 0;
        int arr_len = 10;
        char **arr = malloc(sizeof(char *) * arr_len);
        while (1) {
            if (!ctx->se_names[i]) break;
            if (!arr || i >= arr_len) {
                arr_len *= 2;
                arr = (char **)(realloc(arr, sizeof(char *) * arr_len));
            }
            size_t str1_len = 7; // strlen("__libc_");
            size_t str2_len = strlen(ctx->se_names[i]);
            char *se_name = malloc(str1_len + str2_len + 1);
            memcpy(se_name, "__libc_", str1_len);
            memcpy(se_name + str1_len, ctx->se_names[i], str2_len + 1);
            arr[i] = se_name;
            i++;
        }
        arr[i] = NULL;
        lookup_symbols(ctx->libc, arr);
        
        // free temp sym array
        i = 0;
        char *buf;
        while ((buf = arr[i++]), buf) free(buf);
        free(arr);

        // remove "__libc_" prefix
        SymbolEntry *cse = ctx->libc->se_head;
        while (cse) {
            char *old_name = cse->name;
            cse->name = strdup(cse->name + 7); // 7 == strlen("__libc_")
            if (!cse->offset) {
                cse->type = SE_TYPE_UNRESOLVED;
            }
            free(old_name);
            cse = cse->_next;
        }
        
        // find function signatures in case it's stripped
        ASSERT(ctx->libc, "ctx->libc is NULL. Please report this!");
        show_banner |= evaluate_funcid(ctx->libc);
    }

    show_banner |= evaluate_funcid(ctx->target);

    int i = 0;
    Breakpoint *bp;
    while ((bp = (ctx->pre_analysis_bps)[i++]), bp) {
        SymbolEntry *target_se = find_se_name(ctx->target->se_head, bp->name);
        ASSERT(target_se, "calculate_bp_addrs: target_se missing for name %s", bp->name);

        // create __libc_ version
        SymbolEntry *libc_se = find_se_name(ctx->libc->se_head, bp->name);
        if (libc_se) {
            libc_se->offset += libc_se->_sub_offset; // XXX: this is a stopgap solution for libc. libc is setting a random load addr of 0x40 which is throwing the offset off.
            //debug("libc %s: %s 0x%x (type=%d)\n", ctx->libc_path, libc_se->name, libc_se->offset, libc_se->type);
        }

        uint64_t addr = 0;

        if (ctx->target->is_dynamic && libc_pme && libc_se && libc_se->offset) {
            // prioritize the libc symbols over target's symbols
            addr = libc_pme->base + libc_se->offset;
            debug(". used dynamic libc addr " U64T "\n", addr);
        } else if (target_se->type == SE_TYPE_STATIC) {
            // static symbol in ELF
            addr = bin_pme->base + target_se->offset;
            debug(". used static addr " U64T "\n", addr);
        } else {
            if (target_se->type == SE_TYPE_DYNAMIC || target_se->type == SE_TYPE_DYNAMIC_PLT) {
                // it's a GOT pointer
                if (libc_pme) {
                    uint64_t got_ptr = bin_pme->base + target_se->offset;
                    uint64_t got_val = ptrace(PTRACE_PEEKDATA, ctx->pid, got_ptr, NULL);
                    debug(". used got addr. peeked val=" U64T " at GOT ptr=" U64T " for %s (type=%d)\n", got_val, got_ptr, target_se->name, target_se->type);

                    // check if this is in the PLT or if it's resolved to libc
                    if (target_se->type == SE_TYPE_DYNAMIC_PLT && (got_val >= bin_pme->base && got_val < bin_pme->end)) {
                        // I had issues where GOT contained the address + 0x6, see  https://github.com/Arinerron/heaptrace/issues/22#issuecomment-937420315
                        // see https://www.intezer.com/blog/malware-analysis/executable-linkable-format-101-part-4-dynamic-linking/ for explanation why it's like that
                        got_val -= (uint64_t)0x6;
                    }

                    addr = got_val;
                }
            }
        }

        bp->addr = addr;
    }

    return show_banner;
}


// attempts to identify functions in stripped ELFs (bin_pme->base only, not libc)
uint evaluate_funcid(HeaptraceFile *hf) {
    uint show_banner = 0;
    int _printed_debug = 0;
    FILE *f = fopen(hf->path, "r");
    FunctionSignature *sigs = find_function_signatures(f);
    for (int i = 0; i < 5; i++) {
        FunctionSignature *sig = &sigs[i];
        //printf("(2) -> %s (%p) - %x (%p)\n", sig->name, sig, sig->offset, sig->offset);
        if (sig->offset) {
            uint64_t ptr = sig->offset;
            int j = 0;
            SymbolEntry *se = hf->se_head;
            while (se) {
                if (se->type != SE_TYPE_UNRESOLVED) {
                    se = se->_next;
                    continue;
                }
                if (!strcmp(sig->name, se->name)) {
                    if (!_printed_debug) {
                        _printed_debug = 1;
                        info("Attempting to identify function signatures in " COLOR_LOG_BOLD "%s" COLOR_LOG "...\n", hf->path);
                        show_banner = 1;
                    }
                    info(COLOR_LOG "* found " COLOR_LOG_BOLD "%s" COLOR_LOG " at " PTR ".\n" COLOR_RESET, sig->name, PTR_ARG(sig->offset));
                    se->offset = ptr;
                    se->_sub_offset = 0;
                    se->type = SE_TYPE_STATIC; // to make sure it gets resolved as bin_base+addr
                    break;
                }
                se = se->_next;
            }
        }
    }

    if (sigs) free(sigs);
    fclose(f);
    return show_banner;
}


void end_debugger(HeaptraceContext *ctx, int should_detach) {
    if (ctx == FIRST_CTX) FIRST_CTX = 0; // prevent race condition on free()

    uint _was_sigsegv = 0;
    uint _show_newline = 0;
    log(COLOR_LOG "\n================================= " COLOR_LOG_BOLD "END HEAPTRACE" COLOR_LOG " ================================\n" COLOR_RESET);

    if (ctx->status16 == PTRACE_EVENT_EXEC) {
        log(COLOR_ERROR "Detaching heaptrace because process made a call to exec()");
        should_detach = 1;
        _show_newline = 1;

        // we keep this logic in case someone makes one of the free/malloc hooks call /bin/sh :)
        if (ctx->between_pre_and_post) log(" while executing " COLOR_ERROR_BOLD "%s" COLOR_ERROR " (" SYM COLOR_ERROR ")", ctx->between_pre_and_post, get_oid(ctx));
        log("." COLOR_RESET " ");
    } else if ((ctx->status == STATUS_SIGSEGV) || ctx->status == 0x67f || (WIFSIGNALED(ctx->status) && !WIFEXITED(ctx->status))) { // some other abnormal code
        // XXX: this code checks if the whole `status` int == smth. We prob only want ctx->status16
        log(COLOR_ERROR "Process exited with signal " COLOR_ERROR_BOLD "%d" COLOR_ERROR " (" COLOR_ERROR_BOLD "%s" COLOR_ERROR ")", ctx->code, strsignal(ctx->code));
        if (ctx->between_pre_and_post) log(" while executing " COLOR_ERROR_BOLD "%s" COLOR_ERROR " (" SYM COLOR_ERROR ")", ctx->between_pre_and_post, get_oid(ctx));
        log("." COLOR_RESET " ");
        _was_sigsegv = 1;
        _show_newline = 1;
    }

    if (WCOREDUMP(ctx->status)) {
        log(COLOR_ERROR "Core dumped. " COLOR_LOG);
    }

    if (_show_newline) log("\n");

    show_stats(ctx);

    if (_was_sigsegv) check_should_break(ctx, 1, BREAK_SIGSEGV, 0);
    if (should_detach) {
        _remove_breakpoints(ctx, BREAKPOINT_OPTS_ALL);
        ptrace(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);
    } else {
        kill(ctx->pid, SIGINT);
    }
    free_ctx(ctx);
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


// this is triggered by a breakpoint. The address to _start (entry) is stored 
// in auxv and fetched on the first run.
void _pre_entry(HeaptraceContext *ctx) {
    ctx->should_map_syms = 1;
    _remove_breakpoint(ctx, ctx->bp_entry, BREAKPOINT_OPTS_ALL);
    check_should_break(ctx, 1, BREAK_MAIN, 0);
}


void pre_analysis(HeaptraceContext *ctx) {
    struct {
        char *name;
        void *pre_handler;
        size_t pre_handler_nargs;
        void *post_handler;
    } breakpoint_defs[] = {
        {"malloc", pre_malloc, 1, post_malloc},
        {"calloc", pre_calloc, 2, post_calloc},
        {"free", pre_free, 1, post_free},
        {"realloc", pre_realloc, 2, post_realloc},
        {"reallocarray", pre_reallocarray, 3, post_reallocarray}
    };

    int breakpoint_defs_c = sizeof(breakpoint_defs) / sizeof(breakpoint_defs[0]);
    //Breakpoint *bps[breakpoint_defs_c + 1];
    Breakpoint **bps = (Breakpoint **)malloc(sizeof(Breakpoint *) * (breakpoint_defs_c + 1));
    ctx->pre_analysis_bps = bps;
    //char *se_names[breakpoint_defs_c + 1];
    char **se_names = (char **)malloc(sizeof(char *) * (breakpoint_defs_c + 1));
    ctx->se_names = se_names;

    bps[breakpoint_defs_c] = NULL;
    ctx->se_names[breakpoint_defs_c] = NULL;

    Breakpoint *bp;
    for (int i = 0; i < breakpoint_defs_c; i++) {
        ctx->se_names[i] = breakpoint_defs[i].name;
        bp = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
        bp->name = breakpoint_defs[i].name;
        bp->pre_handler = breakpoint_defs[i].pre_handler;
        bp->pre_handler_nargs = breakpoint_defs[i].pre_handler_nargs;
        bp->post_handler = breakpoint_defs[i].post_handler;
        bps[i] = bp;
    }
    
    debug("Looking up symbols...\n");
    lookup_symbols(ctx->target, ctx->se_names);
}


uint map_syms(HeaptraceContext *ctx) {
    ctx->should_map_syms = 0;
    uint show_banner = 0;

    // parse /proc/pid/maps
    if (!ctx->pme_head) ctx->pme_head = build_pme_list(ctx->pid); // already built if attaching
    ProcMapsEntry *bin_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_BINARY);
    ProcMapsEntry *libc_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_LIBC);
    
    // quick debug info about addresses/paths we found
    ASSERT(bin_pme, "Failed to find target binary in process mapping (!bin_pme). Please report this!");
    debug("found memory maps... binary (%s): " U64T "-" U64T, bin_pme->name, bin_pme->base, bin_pme->end);
    if (libc_pme) {
        char *name = libc_pme->name;
        ctx->libc->path = name;
        if (!name) name = "<UNKNOWN>";
        debug2(", libc (%s): " U64T "-" U64T, name, libc_pme->base, libc_pme->end);
    }
    debug2("\n");

    // print the type of binary etc
    ASSERT(ctx->target, "!ctx->target. Please report this.");
    if (ctx->target->is_dynamic) {
        verbose(COLOR_RESET_BOLD "Dynamically-linked");
        if (ctx->target->is_stripped) verbose(", stripped");
        verbose(" binary")

        if (libc_pme && libc_pme->name) {
            char *ptr = get_libc_version(libc_pme->name);
            char *libc_version = ptr;
            if (!ptr) libc_version = "???";
            verbose(" using glibc version %s (%s)\n" COLOR_RESET, libc_version, libc_pme->name);
            ctx->libc_version = ptr;
        } else { verbose("\n"); }
    } else {
        verbose(COLOR_RESET_BOLD "Statically-linked");
        if (ctx->target->is_stripped) verbose(", stripped");
        verbose(" binary\n" COLOR_RESET);
    }
    if (OPT_VERBOSE) show_banner = 1;

    // now that we know the base addresses, calculate offsets
    show_banner |= calculate_bp_addrs(ctx, ctx->pre_analysis_bps);

    // final attempts to get symbol information (funcid + parse --symbol)
    evaluate_symbol_defs(ctx, ctx->pre_analysis_bps);
    verbose("\n");

    // install breakpoints
    int k = 0;
    Breakpoint *bp;
    while (1) {
        bp = (ctx->pre_analysis_bps)[k++];
        if (!bp) break;
        install_breakpoint(ctx, bp);
    }

    return show_banner;
}


// returns child PID
int start_process(HeaptraceContext *ctx) {
    int child = fork();
    if (!child) {
        // disable ASLR
        if (personality(ADDR_NO_RANDOMIZE) == -1) {
            warn("failed to disable aslr for child\n");
        }

        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        extern char **environ;
        if (execvpe(ctx->target->path, ctx->target_argv, environ) == -1) {
            fatal("failed to start target via execvp(\"%s\", ...): (%d) %s\n", ctx->target->path, errno, strerror(errno)); // XXX: not thread safe
            exit(1);
        }
    }
    return child;
}


void start_debugger(HeaptraceContext *ctx) {
    log(COLOR_LOG "================================ " COLOR_LOG_BOLD "BEGIN HEAPTRACE" COLOR_LOG " ===============================\n" COLOR_RESET);

    if (OPT_ATTACH_PID) {
        ctx->pid = OPT_ATTACH_PID;
        ctx->pme_head = build_pme_list(ctx->pid);
        ProcMapsEntry *bin_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_BINARY);
        if (!bin_pme) {
            fatal("failed to find process %d's binary name. Are you sure you have the right process ID? Does heaptrace have permission to ptrace the target process?\n", OPT_ATTACH_PID);
            exit(1);
        }
        ctx->target->path = bin_pme->name;
        debug("Found pid %d's ctx->target->path: %s\n", ctx->pid, ctx->target->path);
    }
    
    pre_analysis(ctx);
    
    int show_banner = 0;
    //ctx->target->is_dynamic = any_se_type(ctx->target_se_head, SE_TYPE_DYNAMIC) || any_se_type(ctx->target_se_head, SE_TYPE_DYNAMIC_PLT);

    int look_for_brk = ctx->target->is_dynamic;

    if (!OPT_ATTACH_PID) {
        ctx->pid = start_process(ctx);
        debug("Started target process in PID %d\n", ctx->pid);
    } else {
        ctx->pid = OPT_ATTACH_PID;
        info("Attaching to target process PID %d...\n", ctx->pid);
        if (ptrace(PTRACE_ATTACH, ctx->pid, NULL, NULL) == -1) {
            fatal("Failed to attach to process PID %d. Are you sure you have rights to ptrace the process?\n", ctx->pid);
            exit(1);
        }
        show_banner = 1;
    }

    //ctx->should_map_syms = !ctx->target->is_dynamic;
    int set_auxv_bp = !OPT_ATTACH_PID; // XXX: this is confusing. refactor later.
    ctx->should_map_syms = !set_auxv_bp;

    while(KEEP_RUNNING && waitpid(ctx->pid, &(ctx->status), 0)) {
        // update ctx
        ctx->status16 = ctx->status >> 16;
        ctx->code = (ctx->status >> 8) & 0xffff;

        // make sure it catches any fork()/vfork()/clone()/exec()
        ptrace(PTRACE_SETOPTIONS, ctx->pid, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);

        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, ctx->pid, 0, &regs);

        if (set_auxv_bp) {
            set_auxv_bp = 0;

            debug("resolving auxiliary vector AT_ENTRY...\n");
            ctx->target_at_entry = get_auxv_entry(ctx->pid);
            ASSERT(ctx->target_at_entry, "unable to locate at_entry auxiliary vector. Please report this.");
            // temporary solution is to uncomment the should_map_syms = !ctx->target_is_dynamic
            // see blame for this commit, or see commit after commit 2394278.
            
            Breakpoint *bp_entry = (Breakpoint *)malloc(sizeof(struct Breakpoint));
            bp_entry->name = "_entry";
            bp_entry->addr = ctx->target_at_entry;
            bp_entry->pre_handler = _pre_entry;
            bp_entry->pre_handler_nargs = 0;
            bp_entry->post_handler = 0;
            install_breakpoint(ctx, bp_entry);
            ctx->bp_entry = bp_entry;
        }

        if (WIFEXITED(ctx->status) || WIFSIGNALED(ctx->status) || ctx->status == STATUS_SIGSEGV || ctx->status == 0x67f) {
            debug("received an exit status, goodbye!\n");
            end_debugger(ctx, 0);
        } else if (ctx->status == 0x57f) { /* status SIGTRAP */ 
            _check_breakpoints(ctx);
            if (!KEEP_RUNNING) {
                debug("received a SIGTRAP and !KEEP_RUNNING\n");
                break;
            }
        } else if (ctx->status >> 16 == PTRACE_EVENT_FORK || ctx->status >> 16 == PTRACE_EVENT_VFORK || ctx->status >> 16 == PTRACE_EVENT_CLONE) { /* fork, vfork, or clone */
            long newpid;
            ptrace(PTRACE_GETEVENTMSG, ctx->pid, NULL, &newpid);

            if (OPT_FOLLOW_FORK) {
                log_heap(COLOR_RESET COLOR_RESET_BOLD "Detected fork in process (%d->%ld). Following fork...\n\n", ctx->pid, newpid);
                _remove_breakpoints(ctx, BREAKPOINT_OPT_REMOVE);
                ptrace(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);

                ctx->pid = newpid;
                ptrace(PTRACE_SETOPTIONS, ctx->pid, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
                //ptrace(PTRACE_CONT, newpid, 0L, 0L);
            } else {
                debug("detected process fork, use --follow-fork to folow it. Parent PID is %u, child PID is %lu.\n", ctx->pid, newpid);
                // XXX: this is a hack because it needs a context obj. Long 
                // term we will make a another ctx object for each fork and 
                // just pass that in
                uint oldpid = ctx->pid;
                ctx->pid = newpid;
                _remove_breakpoints(ctx, BREAKPOINT_OPT_REMOVE);
                ptrace(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);
                kill(ctx->pid, SIGCONT);
                ctx->pid = oldpid;
            }
        } else if (ctx->status16 == PTRACE_EVENT_EXEC) {
            debug("Detected exec() call, detaching...\n");
            end_debugger(ctx, 1);
        } else {
            debug("warning: hit unknown status code %d (16: %d)\n", ctx->status, ctx->status16);
        }

        if (ctx->should_map_syms) {
            show_banner |= map_syms(ctx);
            if (ctx->target->is_stripped && ctx->libc->is_stripped && !strlen(symbol_defs_str)) {
                warn("Binary appears to be stripped or does not use the glibc heap; heaptrace was not able to resolve any symbols. Please specify symbols via the -s/--symbols argument. e.g.:\n\n      heaptrace --symbols 'malloc=libc+0x100,free=libc+0x200,realloc=bin+123' ./binary\n\nSee the help guide at https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary\n");
                show_banner = 1;
            }

            if (show_banner) {
                log(COLOR_LOG "================================================================================\n" COLOR_RESET);
            }
            log("\n");

        }

        ptrace(PTRACE_CONT, ctx->pid, NULL, NULL);
    }

    if (KEEP_RUNNING) {
        warn("while loop exited. Please report this. Status: %d, exit status: %d\n", ctx->status, WEXITSTATUS(ctx->status));
    } else {
        KEEP_RUNNING = 1; // prevent end_debugger() race condition
        end_debugger(ctx, 1);
    }
}
