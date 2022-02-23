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
#include "user-breakpoint.h"

static int in_breakpoint = 0;

int OPT_FOLLOW_FORK = 0;

void _check_breakpoints(HeaptraceContext *ctx, struct user_regs_struct *regs_ptr) {
    struct user_regs_struct regs = *regs_ptr;
    uint64_t reg_rip = (uint64_t)regs.rip - 1;

    int _was_bp = 0;

    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        Breakpoint *bp = ctx->breakpoints[i];
        if (bp) {
            if (bp->addr == reg_rip) { // hit the breakpoint
                _was_bp = 1;
                PTRACE(PTRACE_POKEDATA, ctx->pid, reg_rip, (uint64_t)bp->orig_data);

                // move rip back by one
                regs.rip = reg_rip; // NOTE: this is actually $rip-1
                PTRACE(PTRACE_SETREGS, ctx->pid, NULL, &regs);
                
                ctx->h_when = UBP_WHEN_BEFORE;
                
                if (!in_breakpoint && !bp->_is_inside) {
                    reset_handler_log_message(ctx);
                    if (bp->pre_handler) {
                        int nargs = bp->pre_handler_nargs;
                        ctx->hlm.func_name = bp->func_name;
                        ctx->hlm.ret_options = bp->ret_options;
                        if (ctx->hlm.func_name) memcpy(ctx->hlm.arg_options, bp->arg_options, sizeof(uint) * 3);
                        ctx->hlm.arg_ptr[0] = regs.rdi;
                        ctx->hlm.arg_ptr[1] = regs.rsi;
                        ctx->hlm.arg_ptr[2] = regs.rdx;
                        ctx->between_pre_and_post = bp->func_name;
                        print_handler_log_message_1(ctx);
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

                        color_log(COLOR_ERROR_BOLD); // this way any errors inside func are bold red
                    }
                }

                // TODO: see if we can move this into the previous if block
                ctx->h_when = UBP_WHEN_BEFORE;
                check_should_break(ctx);
                
                // reset breakpoint and continue
                PTRACE(PTRACE_SINGLESTEP, ctx->pid, NULL, NULL);
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
                                        ctx->h_ret_ptr_section_type = pme->pet;
                                        ctx->h_ret_ptr = val_at_reg_rsp;
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
                        PTRACE(PTRACE_POKEDATA, ctx->pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                    } else { // this is a return value catcher breakpoint
                        Breakpoint *orig_bp = bp->_bp;
                        if (orig_bp) {
                            ctx->h_when = UBP_WHEN_AFTER;
                            if (orig_bp->post_handler) {
                                ((void(*)(HeaptraceContext *, uint64_t))orig_bp->post_handler)(ctx, regs.rax);
                            }
                            ctx->h_when = UBP_WHEN_AFTER;
                            ctx->hlm.ret_ptr = regs.rax;
                            print_handler_log_message_2(ctx);
                            check_should_break(ctx);
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
                    PTRACE(PTRACE_POKEDATA, ctx->pid, reg_rip, ((uint64_t)bp->orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
                }
                ctx->between_pre_and_post = 0;
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
                        info("Attempting to identify function signatures in ");
                        color_log(COLOR_LOG_BOLD);
                        log("%s", hf->path);
                        color_log(COLOR_LOG); 
                        log("...\n");
                        show_banner = 1;
                    }
                    info("* found ");
                    color_log(COLOR_LOG_BOLD);
                    log("%s", sig->name);
                    color_log(COLOR_LOG);
                    log(" at " PTR ".\n", PTR_ARG(sig->offset));
                    color_log(COLOR_RESET);
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
    ctx->h_state = PROCESS_STATE_STOPPED;

    uint _was_sigsegv = 0;
    uint _show_newline = 0;
    color_log(COLOR_LOG);

    log("\n");
    print_header_bars("END HEAPTRACE", 13);

    if (ctx->status16 == PTRACE_EVENT_EXEC) {
        color_log(COLOR_ERROR);
        log("Detaching heaptrace because process made a call to exec()");
        should_detach = 1;
        _show_newline = 1;

        // we keep this logic in case someone makes one of the free/malloc hooks call /bin/sh :)
        if (ctx->between_pre_and_post) log(" while executing " COLOR_ERROR_BOLD "%s" COLOR_ERROR " (" SYM COLOR_ERROR ")", ctx->between_pre_and_post, GET_OID());
        log(".");
        color_log(COLOR_RESET);
        log(" ");
    } else if ((ctx->status == STATUS_SIGSEGV) || ctx->status == 1919 || ctx->status == 1151 || ctx->status == 0x67f || (WIFSIGNALED(ctx->status) && !WIFEXITED(ctx->status))) { // some other abnormal code
        // XXX: this code checks if the whole `status` int == smth. We prob only want ctx->status16
        color_log(COLOR_ERROR);
        log("Process exited with signal ");
        color_log(COLOR_ERROR_BOLD);
        log("%s", strsignal(ctx->code));
        color_log(COLOR_ERROR);
        log(" (");
        color_log(COLOR_ERROR_BOLD);
        log("%d", ctx->code);
        color_log(COLOR_ERROR);
        log(")");
        if (ctx->between_pre_and_post) log(" while executing " COLOR_ERROR_BOLD "%s" COLOR_ERROR " (" SYM COLOR_ERROR ")", ctx->between_pre_and_post, GET_OID());
        log(".");
        color_log(COLOR_RESET);
        log(" ");
        _was_sigsegv = 1;
        _show_newline = 1;
    }

    if (WCOREDUMP(ctx->status)) {
        color_log(COLOR_ERROR);
        log("Core dumped. ");
        color_log(COLOR_LOG);
    }

    if (_show_newline) log("\n");

    show_stats(ctx);

    if (_was_sigsegv) {
        ctx->h_state = PROCESS_STATE_SEGFAULT;
        ctx->h_when = UBP_WHEN_BEFORE;
        check_should_break(ctx);
        ctx->h_when = UBP_WHEN_AFTER;
    }

    if (should_detach) {
        _remove_breakpoints(ctx, BREAKPOINT_OPTS_ALL);
        PTRACE(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);
    } else {
        kill(ctx->pid, SIGINT);
    }

    cleanup_and_exit(ctx, 0);
}


char *get_libc_version(char *libc_path) {
    FILE *f = fopen(libc_path, "r");
    if (!f) return 0;
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *string = malloc(fsize + 1);
    size_t dummy = fread(string, 1, fsize, f);
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
    ctx->h_state = PROCESS_STATE_ENTRY;
    ctx->should_map_syms = 1;
    _remove_breakpoint(ctx, ctx->bp_entry, BREAKPOINT_OPTS_ALL);
    ctx->h_when = UBP_WHEN_BEFORE;
    check_should_break(ctx);
    ctx->h_when = UBP_WHEN_AFTER;
    ctx->h_state = PROCESS_STATE_RUNNING;
}

const struct {
    char *name;
    void *pre_handler;
    size_t pre_handler_nargs;
    void *post_handler;
    uint arg_options[3];
    uint ret_options;
} breakpoint_defs[] = {
    {"malloc", pre_malloc, 1, post_malloc, {HLM_OPTION_SIZE, 0, 0}, 1},
    {"calloc", pre_calloc, 2, post_calloc, {HLM_OPTION_SIZE, HLM_OPTION_SIZE, 0}, 1},
    {"free", pre_free, 1, post_free, {HLM_OPTION_SYMBOL, 0, 0}, 0},
    {"realloc", pre_realloc, 2, post_realloc, {HLM_OPTION_SYMBOL, HLM_OPTION_SIZE, 0}, 1},
    {"reallocarray", pre_reallocarray, 3, post_reallocarray, {HLM_OPTION_SYMBOL, HLM_OPTION_SIZE, HLM_OPTION_SIZE}, 1}
};

static uint pre_analysis(HeaptraceContext *ctx) {
    int breakpoint_defs_c = sizeof(breakpoint_defs) / sizeof(breakpoint_defs[0]);
    size_t ubp_sym_refs_c = count_symbol_references((char **)0);

    Breakpoint **bps = (Breakpoint **)calloc(breakpoint_defs_c + 1, sizeof(Breakpoint *));
    ctx->pre_analysis_bps = bps;

    size_t se_names_sz = sizeof(char *) * (breakpoint_defs_c + ubp_sym_refs_c + 1);
    char **se_names = (char **)malloc(se_names_sz);
    ctx->se_names = se_names;


    bps[breakpoint_defs_c] = NULL;
    count_symbol_references(&(ctx->se_names[breakpoint_defs_c]));
    ctx->se_names[breakpoint_defs_c + ubp_sym_refs_c] = NULL;

    Breakpoint *bp;
    for (int i = 0; i < breakpoint_defs_c; i++) {
        ctx->se_names[i] = breakpoint_defs[i].name;
        bp = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
        bp->name = breakpoint_defs[i].name;
        bp->pre_handler = breakpoint_defs[i].pre_handler;
        bp->pre_handler_nargs = breakpoint_defs[i].pre_handler_nargs;
        bp->post_handler = breakpoint_defs[i].post_handler;

        // for HLM logging
        bp->func_name = breakpoint_defs[i].name;
        bp->ret_options = breakpoint_defs[i].ret_options;
        //bp->arg_options = calloc(sizeof(breakpoint_defs[i].arg_options) + 1);
        memcpy(bp->arg_options, breakpoint_defs[i].arg_options, sizeof(breakpoint_defs[i].arg_options));

        bps[i] = bp;
    }
    
    debug("Looking up symbols...\n");
    return lookup_symbols(ctx->target, ctx->se_names);
}


uint map_syms(HeaptraceContext *ctx) {
    ctx->should_map_syms = 0;
    uint show_banner = 0;

    // parse /proc/pid/maps
    if (!ctx->pme_head) ctx->pme_head = build_pme_list(ctx->pid); // already built if attaching
    ProcMapsEntry *bin_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_BINARY);
    ProcMapsEntry *libc_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_LIBC);
    ctx->target->pme = bin_pme;
    ctx->libc->pme = libc_pme;
    
    // quick debug info about addresses/paths we found
    ASSERT(bin_pme, "failed to find target binary in process mapping (!bin_pme). Please report this!");
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
    color_verbose(COLOR_RESET COLOR_RESET_BOLD);
    if (ctx->target->is_dynamic) {
        verbose("Dynamically-linked");
        if (ctx->target->is_stripped) verbose(", stripped");
        verbose(" binary")

        if (libc_pme && libc_pme->name) {
            char *ptr = get_libc_version(libc_pme->name);
            char *libc_version = ptr;
            if (!ptr) libc_version = "???";
            verbose(" using glibc version %s (%s)\n", libc_version, libc_pme->name);
            ctx->libc_version = ptr;
        } else { verbose("\n"); }
    } else {
        verbose("Statically-linked");
        if (ctx->target->is_stripped) verbose(", stripped");
        verbose(" binary\n");
    }
    color_verbose(COLOR_RESET);
    if (OPT_VERBOSE) show_banner = 1;

    // now that we know the base addresses, calculate offsets
    show_banner |= calculate_bp_addrs(ctx, ctx->pre_analysis_bps);

    // final attempts to get symbol information (funcid + parse --symbol)
    evaluate_symbol_defs(ctx, ctx->pre_analysis_bps);

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
            warn("failed to disable ASLR for child\n");
        }

        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            // ^ if this fails, process is likely being traced already. We aren't 
            // going to have permission to trace it. because of that. So it's 
            // going to run without our control and will likely 
            fatal("failed to enable PTRACE_TRACEME on child process (pid=%d)\n", getpid());
            color_log(COLOR_WARN);
            log("hint: is another process tracing heaptrace with follow fork mode enabled? That process likely detected our exec() call to start the target process and took control.\n");
            color_log(COLOR_RESET);
            KEEP_RUNNING = 0;
            abort();
        }

        extern char **environ;
        debug("child process (pid=%d) about to execvpe...\n", getpid());
        if (execvpe(ctx->target->path, ctx->target_argv, environ) == -1) {
            fatal("failed to start target via execvp(\"%s\", ...): (%d) %s\n", ctx->target->path, errno, strerror(errno)); // XXX: not thread safe
            exit(1);
        }
    } else {
        debug("parent process (pid=%d) returning...\n", getpid());
    }
    return child;
}


void start_debugger(HeaptraceContext *ctx) {
    color_log(COLOR_LOG);

    print_header_bars("BEGIN HEAPTRACE", 15);

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
    

    int show_banner = 0;
    if (!OPT_ATTACH_PID) {
        ctx->pid = start_process(ctx);
        debug("Started target process in PID %d\n", ctx->pid);
    } else {
        ctx->pid = OPT_ATTACH_PID;
        info("Attaching to target process PID %d...\n", ctx->pid);
        if (ptrace(PTRACE_ATTACH, ctx->pid, NULL, NULL) == -1) {
            fatal("failed to attach to process PID %d. Are you sure you have rights to ptrace the process?\n", ctx->pid);
            exit(1);
        }
        show_banner = 1;
    }


    //ctx->target->is_dynamic = any_se_type(ctx->target_se_head, SE_TYPE_DYNAMIC) || any_se_type(ctx->target_se_head, SE_TYPE_DYNAMIC_PLT);
    
    //ctx->should_map_syms = !ctx->target->is_dynamic;
    int set_auxv_bp = !OPT_ATTACH_PID; // XXX: this is confusing. refactor later.
    ctx->should_map_syms = !set_auxv_bp;

    int first_run = 1;
    while(KEEP_RUNNING && waitpid(ctx->pid, &(ctx->status), 0) != -1) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, ctx->pid, NULL, &regs) != -1) {
            ctx->h_rip = regs.rip;
        }
        
        // we have to do a waitpid(), otherwise the process name is still 
        // /path/to/heaptrace. We need the correct path for pre_analysis. But 
        // we need the pre_analysis for look_for_brk too.
        if (first_run) {
            first_run = 0;

            ctx->target->path = get_path_by_pid(ctx->pid);
            if (!(ctx->target->path) || !pre_analysis(ctx)) {
                warn("unable to analyze process that is not running.\n");
                color_log(COLOR_WARN);
                log("hint: are you sure you gave heaptrace the correct path to the binary file?\n");
                color_log(COLOR_RESET);
                end_debugger(ctx, 0);
            }

            ctx->h_state = PROCESS_STATE_RUNNING;
        }

        if (!KEEP_RUNNING) break; // in case it updates during waitpid
        // update ctx
        ctx->status16 = ctx->status >> 16;
        ctx->code = (ctx->status >> 8) & 0xffff;

        if (set_auxv_bp) {
            set_auxv_bp = 0;

            // make sure the process is still alive.
            // XXX: a bit of a hack. TODO find a better way to do this.
            char *fname = get_path_by_pid(ctx->pid);
            if (!fname) {
                debug("tracee process (pid=%d) seems to have died before we got a chance to analyze it.\n", ctx->pid);
                warn("unable to trace process; it seems to have died.\n");
                color_log(COLOR_WARN);
                log("hint: are you sure you gave heaptrace the correct path to the binary file?\n");
                color_log(COLOR_RESET);
                end_debugger(ctx, 0);
            } else {
                free(fname);
            }

            debug("resolving auxiliary vector AT_ENTRY...\n");
            ctx->target_at_entry = get_auxv_entry(ctx->pid);
            ASSERT(ctx->target_at_entry, "unable to locate at_entry auxiliary vector. Please report this.");
            // temporary solution is to uncomment the should_map_syms = !ctx->target_is_dynamic
            // see blame for this commit, or see commit after commit 2394278.
            
            Breakpoint *bp_entry = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
            bp_entry->name = "_entry";
            bp_entry->addr = ctx->target_at_entry;
            bp_entry->pre_handler = _pre_entry;
            bp_entry->pre_handler_nargs = 0;
            bp_entry->post_handler = 0;
            install_breakpoint(ctx, bp_entry);
            ctx->bp_entry = bp_entry;
        }

        if (WIFEXITED(ctx->status) || WIFSIGNALED(ctx->status) || ctx->status == STATUS_SIGSEGV || ctx->status == 0x67f || ctx->status == 1151 || ctx->status == 1919) {
            debug("received an exit status, goodbye!\n");
            end_debugger(ctx, 0);
        } else if (ctx->status == 0x57f) { /* status SIGTRAP */ 
            ctx->h_state = PROCESS_STATE_RUNNING;
            _check_breakpoints(ctx, &regs);
            if (!KEEP_RUNNING) {
                debug("received a SIGTRAP and !KEEP_RUNNING\n");
                break;
            }
        } else if (ctx->status >> 16 == PTRACE_EVENT_FORK || ctx->status >> 16 == PTRACE_EVENT_VFORK || ctx->status >> 16 == PTRACE_EVENT_CLONE) { /* fork, vfork, or clone */
            long newpid;
            PTRACE(PTRACE_GETEVENTMSG, ctx->pid, NULL, &newpid);

            if (OPT_FOLLOW_FORK) {
                color_log(COLOR_RESET COLOR_RESET_BOLD);
                log_heap("Detected fork in process (%d->%ld). Following fork...\n", ctx->pid, newpid);
                _remove_breakpoints(ctx, BREAKPOINT_OPT_REMOVE);
                wait(NULL);
                PTRACE(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);

                ctx->pid = newpid;
            } else {
                debug("detected process fork, use --follow-fork to folow it. Parent PID is %u, child PID is %lu.\n", ctx->pid, newpid);
                // XXX: this is a hack because it needs a context obj. Long 
                // term we will make a another ctx object for each fork and 
                // just pass that in
                uint oldpid = ctx->pid;
                ctx->pid = newpid;
                _remove_breakpoints(ctx, BREAKPOINT_OPT_REMOVE);
                int status;
                wait(NULL);
                PTRACE(PTRACE_DETACH, ctx->pid, NULL, SIGCONT);
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
            fill_symbol_references(ctx);
            if (ctx->target->is_stripped && ctx->libc->is_stripped && !strlen(symbol_defs_str)) {
                warn("Binary appears to be stripped or does not use the glibc heap; heaptrace was not able to resolve any symbols. Please specify symbols via the -s/--symbols argument. e.g.:\n\n      heaptrace --symbols 'malloc=libc+0x100,free=libc+0x200,realloc=bin+123' ./binary\n\nSee the help guide at https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary\n");
                show_banner = 1;
            }

            if (show_banner) {
                color_log(COLOR_LOG);
                print_header_bars(0, 0);
                color_log(COLOR_RESET);
            }
            log("\n");

        }

        PTRACE(PTRACE_SETOPTIONS, ctx->pid, NULL, PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXEC);
        PTRACE(PTRACE_CONT, ctx->pid, NULL, NULL);
    }

    if (KEEP_RUNNING) {
        warn("while loop exited. Please report this. Status: %d, exit status: %d\n", ctx->status, WEXITSTATUS(ctx->status));
    } else {
        KEEP_RUNNING = 1; // prevent end_debugger() race condition
        end_debugger(ctx, 1);
    }
}
