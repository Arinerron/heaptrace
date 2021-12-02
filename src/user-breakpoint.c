#include "logging.h"
#include "util.h"
#include "user-breakpoint.h"
#include "debugger.h"

UserBreakpoint *USER_BREAKPOINT_HEAD = 0;
char *OPT_GDB_PATH = "/usr/bin/gdb";


/* SECTION: TOKENIZATION */


static UserBreakpointToken *_create_token(char *s, size_t s_sz, UBPTType type, size_t i) {
    UserBreakpointToken *token = (UserBreakpointToken *)calloc(1, sizeof(UserBreakpointToken));
    token->type = type;
    token->value = calloc(1, s_sz + 2);
    strncpy(token->value, s, s_sz);
    token->i = i;
    debug("... adding token \"%s\" of type=%d\n", token->value, token->type);
    return token;
}


static void _free_token_list(UserBreakpointToken *token) {
    while (token) {
        UserBreakpointToken *next_token = token->next;
        free(token->value);
        free(token);
        token = next_token;
    }
}


UserBreakpointToken *tokenize_user_breakpoint_str(char *breakpoint) {
    UserBreakpointToken *token_head = 0;

    char *start_ptr = breakpoint;
    uint in_token = 0;
    UserBreakpointToken *cur_token = 0;
    UserBreakpointToken *next_token = 0;

    debug("Tokenizing \"%s\"...\n", breakpoint);
    for (size_t i = 0; i < strlen(breakpoint) + 1; i++) {
        char *s = breakpoint + i;
        char c = *s;

        if (!in_token) {
            if (c == ' ' || c == '\t' || c == '\n' || c == '#') {
                // skip whitespace
                continue;
            } else {
                // start token
                start_ptr = s;
                in_token = 1;
            }
        }

        uint in_punctuator = 0;
        if (c == ':' || c == '+' || c == '-' || c == '=' || c == ',' || c == ';') {
            in_punctuator = 1;
        } else if ((c == '&' && *(s + 1) == '&') || (c == '|' && *(s + 1) == '|')) {
            in_punctuator = 2;
        }

        if (start_ptr != s) { // if in the middle of a token    
            if (in_punctuator || c == '\0' || c == ' ' || c == '\t' || c == '\n') {
                next_token = _create_token(start_ptr, s - start_ptr, UBPT_TYPE_IDENTIFIER, i - (s - start_ptr));
                if (!token_head) token_head = next_token;
                if (cur_token) cur_token->next = next_token;
                cur_token = next_token;
                start_ptr = s;
                in_token = 0;
            }
        }

        if (in_punctuator) {
            next_token = _create_token(start_ptr, in_punctuator, UBPT_TYPE_PUNCTUATOR, i - (s - start_ptr));
            if (!token_head) token_head = cur_token;
            if (cur_token) cur_token->next = next_token;
            cur_token = next_token;
            i += (in_punctuator - 1);
            s += (in_punctuator - 1);
            in_token = 0;
        }
    }

    return token_head;
}


/* SECTION: TOKEN TO AST CONVERSION */


static void _expect_token(UserBreakpoint *ubp, UserBreakpointToken *cur_token, uint b, char *msg) {
    if (!b) {
        log("\n");
        fatal("invalid user breakpoint syntax\n");
        log(COLOR_ERROR "    %s\n", ubp->name);
        char *space_buf = calloc(1, cur_token->i + 2);
        memset(space_buf, ' ', cur_token->i);
        log(COLOR_ERROR "    %s^-- %s\n\n" COLOR_RESET, space_buf, msg);
        free(space_buf);
        exit(1); // XXX: leaking unfreed ctx 
    }
}


#define EXPECT(b, msg) _expect_token(ubp, cur_token, (b), (msg))
#define GET() EXPECT(cur_token && cur_token->next, "expected a token following this one"); cur_token = cur_token->next;
#define NEXT() (UserBreakpointToken *)(cur_token && cur_token->next ? cur_token->next : 0)


static UserBreakpointToken *_parse_token_expression(UserBreakpoint *ubp, UserBreakpointToken *cur_token) {
    ubp->address = (UserBreakpointAddress *)calloc(1, sizeof(UserBreakpointAddress));
    UserBreakpointAddress *cur_ubpa = ubp->address;
    cur_ubpa->operation = UBPA_OPERATION_ADD;

    EXPECT(!!cur_token, "expression missing");
    uint _cur_ubpa_filled = 0;
    while (1) {
        if (cur_token->type == UBPT_TYPE_PUNCTUATOR) {
            // if this isn't the first run...
            if (_cur_ubpa_filled) {
                // save current ubpa
                UserBreakpointAddress *next_ubpa = (UserBreakpointAddress *)calloc(1, sizeof(UserBreakpointAddress));
                cur_ubpa->next_operation = next_ubpa;
                cur_ubpa = next_ubpa;
                cur_ubpa->operation = UBPA_OPERATION_ADD;
                _cur_ubpa_filled = 0;
            }

            if (!strcmp(cur_token->value, "+")) {
            } else if (!strcmp(cur_token->value, "-")) {
                if (cur_ubpa->operation == UBPA_OPERATION_SUBTRACT) { // --
                    cur_ubpa->operation = UBPA_OPERATION_ADD;
                } else {
                    cur_ubpa->operation = UBPA_OPERATION_SUBTRACT; // +-
                }
            } else if (!strcmp(cur_token->value, ":")) {
                break;
            } else {
                EXPECT(0, "invalid operation");
            }

            EXPECT(!!NEXT(), "missing expression after operator");
        } else { // cur_token->type == UBPT_TYPE_IDENTIFIER
            _cur_ubpa_filled = 1;
            if (is_uint(cur_token->value) || (strlen(cur_token->value) > 2 && is_uint_hex(cur_token->value + 2) && (
                            cur_token->value[0] == '0' && (cur_token->value[1] == 'x' || cur_token->value[1] == 'o' || cur_token->value[1] == 'b')))) {
                int endp;
                cur_ubpa->address = str_to_uint64(cur_token->value);
            } else {
                cur_ubpa->symbol_name = strdup(cur_token->value);
            }
        }

        cur_token = cur_token->next;
        if (!cur_token) break; // make sure this while look runs at least once
    }

    UserBreakpointAddress *ccur_ubpa = ubp->address;
    while (ccur_ubpa) {
        ccur_ubpa = ccur_ubpa->next_operation;
    }
    return cur_token;
}


UserBreakpoint *_parse_token_list(char *name, UserBreakpointToken **_cur_token) {
    UserBreakpointToken *cur_token = *_cur_token;
    if (!cur_token) return 0;

    UserBreakpoint *ubp = (UserBreakpoint *)calloc(1, sizeof(UserBreakpoint));
    ubp->name = strdup(name + cur_token->i);
    ubp->when = UBP_WHEN_BEFORE;
    ubp->count = 1;
    
    enum action {ACTION_WHAT, ACTION_ADDRESS, ACTION_COUNT} cur_action = ACTION_WHAT;
    while (cur_token) {
        if (cur_action == ACTION_WHAT) {
            if ((cur_token->type == UBPT_TYPE_PUNCTUATOR && (!strcmp(cur_token->value, "||") || !strcmp(cur_token->value, ";") || !strcmp(cur_token->value, ","))) || !strcmp(cur_token->value, "or") || !strcmp(cur_token->value, "OR")) {
                *(ubp->name + cur_token->i) = '\x00';
                GET()
                EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "expected an identifier");
                UserBreakpoint *next_ubp = _parse_token_list(name, &cur_token);
                ubp->next = next_ubp;
                break;
            } else if ((cur_token->type == UBPT_TYPE_PUNCTUATOR && (!strcmp(cur_token->value, "&&"))) || !strcmp(cur_token->value, "and") || !strcmp(cur_token->value, "AND")) {
                *(ubp->name + cur_token->i) = '\x00';
                GET()
                EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "expected an identifier");
                UserBreakpoint *next_ubp = _parse_token_list(name, &cur_token);
                ubp->next_requirement = next_ubp;
                break;
            } else {
                EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "expected an identifier");
                if (!strcmp(cur_token->value, "address") || !strcmp(cur_token->value, "addr")) {
                    ubp->what = UBP_WHAT_ADDRESS;
                    cur_action = ACTION_ADDRESS;
                    GET();
                    EXPECT(cur_token->type == UBPT_TYPE_PUNCTUATOR && !strcmp(cur_token->value, "="), "unexpected token");
                } else if (!strcmp(cur_token->value, "oid") || !strcmp(cur_token->value, "operation") || !strcmp(cur_token->value, "number") || is_uint(cur_token->value)) {
                    ubp->what = UBP_WHAT_OID;
                    if (!is_uint(cur_token->value)) {
                        GET();
                        EXPECT(cur_token->type == UBPT_TYPE_PUNCTUATOR && !strcmp(cur_token->value, "="), "unexpected token");
                        GET();
                        EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "unexpected token type; expecting an identifier");
                    }
                    ubp->oid = (size_t)str_to_uint64(cur_token->value);
                    if (!(ubp->oid)) warn("heaptrace operation IDs (oid) are indexed starting at 1, but user breakpoint is set to oid=0\n");
                } else if (!strcmp(cur_token->value, "segfault") || !strcmp(cur_token->value, "sigsegv") || !strcmp(cur_token->value, "segv") || !strcmp(cur_token->value, "abort")) {
                    ubp->what = UBP_WHAT_SEGFAULT;
                    break;
                } else if (!strcmp(cur_token->value, "main") || !strcmp(cur_token->value, "entry") || !strcmp(cur_token->value, "start") || !strcmp(cur_token->value, "_entry") || !strcmp(cur_token->value, "_start")) {
                    ubp->what = UBP_WHAT_ENTRY;
                    break;
                } else {
                    EXPECT(0, "unknown 'what': please choose one of [oid, address, segfault/sigsegv/segv/abort, entry/main/start/_start/_entry]");
                }
            }
        } else if (cur_action == ACTION_ADDRESS) {
            cur_token = _parse_token_expression(ubp, cur_token);
            cur_action = ACTION_COUNT;
        } else if (cur_action == ACTION_COUNT) {
            EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "expected identifier 'count'");
            ubp->count = (size_t)str_to_uint64(cur_token->value);
            break; // if you're adding &&/AND support, start by setting cur_action here
            // actually tbh just call self again...
        }

        cur_token = NEXT();
        continue;

expect_address:;
        cur_action = ACTION_ADDRESS;
        GET();
        EXPECT(cur_token->type == UBPT_TYPE_PUNCTUATOR && !strcmp(cur_token->value, "="), "unexpected token");
        GET();
        continue;
    }

    *_cur_token = cur_token;
    return ubp;
}


UserBreakpoint *create_user_breakpoint(char *name) {
    UserBreakpointToken *token_head = tokenize_user_breakpoint_str(name);
    UserBreakpointToken *cur_token = token_head;
    UserBreakpoint *ubp = _parse_token_list(name, &cur_token);
    _free_token_list(token_head);
    return ubp;
}


void insert_user_breakpoint(UserBreakpoint *ubp) {
    if (!USER_BREAKPOINT_HEAD) {
        USER_BREAKPOINT_HEAD = ubp;
    } else {
        UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
        while(cur_ubp->next) { cur_ubp = cur_ubp->next; }
        cur_ubp->next = ubp;
    }
}


static void free_address_list(UserBreakpointAddress *ubpa) {
    if (!ubpa) return;
    free(ubpa->symbol_name);
    free_address_list(ubpa->next_operation);
}


void free_user_breakpoints() {
    UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
    while (cur_ubp) {
        free_address_list(cur_ubp->address);
        free(cur_ubp->name);
        cur_ubp = cur_ubp->next;
    }
}


/* SECTION: CHECKING BREAKPOINTS */


static inline uint _is_reference_constant(char *name) {
    if (!strcmp(name, "bin") || !strcmp(name, "libc") || !strcmp(name, "binary") || !strcmp(name, "target")) {
        return 1;
    }

    return 0;
}


size_t count_symbol_references(char **se_names) {
    size_t count = 0;
    UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
    while (cur_ubp) {
        UserBreakpointAddress *cur_ubpa = cur_ubp->address;
        while (cur_ubpa) {
            if (cur_ubpa->symbol_name) {
                if (!_is_reference_constant(cur_ubpa->symbol_name)) {
                    if (se_names) {
                        se_names[count] = strdup(cur_ubpa->symbol_name);
                    }
                    count++;
                }
            }
            cur_ubpa = cur_ubpa->next_operation;
        }
        cur_ubp = cur_ubp->next;
    }
    return count;
}


static inline uint64_t _evaluate_user_breakpoint_address(UserBreakpoint *ubp) {
    ASSERT(!!ubp->address, "what=address, but address is NULL. Please report this along with your command line arguments.");
    uint64_t ptr = 0;
    UserBreakpointAddress *cur_ubpa = ubp->address;
    while (cur_ubpa) {
        uint64_t cur_ptr = cur_ubpa->address;
        ASSERT(!(cur_ubpa->symbol_name), "unable to check user breakpoint \"%s\"; symbol \"%s\" not resolved", ubp->name, cur_ubpa->symbol_name);
        // NOTE: this assertion is gonna fail if we use `entry`!

        if (cur_ubpa->operation == UBPA_OPERATION_ADD) {
            ptr += cur_ptr;
        } else if (cur_ubpa->operation == UBPA_OPERATION_SUBTRACT) {
            ptr -= cur_ptr;
        } else {
            ASSERT(0, "unknown operation %d. Please report this!", cur_ubpa->operation);
        }

        cur_ubpa = cur_ubpa->next_operation;
    }
    return ptr;
}


// this is triggered by user breakpoints
void _pre_user_breakpoint(HeaptraceContext *ctx) {
    ctx->h_state = PROCESS_STATE_RUNNING;
    ctx->h_when = UBP_WHEN_CUSTOM_BP; // only triggers on _pre_user_breakpoint that way
    check_should_break(ctx);
}


void install_user_breakpoints(HeaptraceContext *ctx) {
    UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
    while (cur_ubp) {
        if (cur_ubp->what == UBP_WHAT_ADDRESS) {
            Breakpoint *bp = (Breakpoint *)calloc(1, sizeof(struct Breakpoint));
            bp->name = strdup(cur_ubp->name);
            bp->addr = cur_ubp->address_eval;
            bp->pre_handler = _pre_user_breakpoint;
            bp->pre_handler_nargs = 0;
            install_breakpoint(ctx, bp);
        }
        cur_ubp = cur_ubp->next;
    }
}


static void _fill_symbol_references(HeaptraceContext *ctx, ProcMapsEntry *bin_pme, ProcMapsEntry *libc_pme, UserBreakpoint *cur_ubp) {
    UserBreakpointAddress *cur_ubpa = cur_ubp->address;
    while (cur_ubpa) {
        if (cur_ubpa->symbol_name) {
            if (!_is_reference_constant(cur_ubpa->symbol_name)) {
                uint resolved = 0;
                SymbolEntry *cur_se = ctx->target->se_head;
                while (cur_se) {
                    if (!strcmp(cur_ubpa->symbol_name, cur_se->name)) {
                        // found the symbol!
                        cur_ubpa->symbol_name = 0;
                        if (cur_se->type == SE_TYPE_UNRESOLVED) {
                            log("\n");
                            fatal("failed to resolve symbol \"%s\" referenced in user breakpoint \"%s\".\n", cur_se->name, cur_ubp->name);
                            end_debugger(ctx, 0);
                        } else if (cur_se->type != SE_TYPE_STATIC) {
                            log("\n");
                            fatal("user breakpoint \"%s\" references symbol %s which is a dynamic symbol. Only static symbols are currently supported. You may use the `libc` variable to reference the glibc base address instead.\n", cur_ubp->name, cur_se->name);
                            end_debugger(ctx, 0);
                        } else {
                            cur_ubpa->address = bin_pme->base + cur_se->offset;
                            if (ctx->target->is_dynamic) cur_ubpa->address += cur_se->_sub_offset;
                        }
                        resolved = 1;
                        break;
                    }
                    cur_se = cur_se->_next;
                }

                if (!resolved) {
                    warn("user breakpoint \"%s\" references %s but the symbol could not be resolved. Will assume symbol %s=0x0\n", cur_ubp->name, cur_ubpa->symbol_name, cur_ubpa->symbol_name);
                    cur_ubpa->symbol_name = 0;
                    cur_ubpa->address = 0;
                }
            } else {
                if (!strcmp(cur_ubpa->symbol_name, "libc")) {
                    if (!(ctx->target->is_dynamic)) {
                        warn("user breakpoint \"%s\" references %s but target binary is statically linked\n", cur_ubp->name, cur_ubpa->symbol_name);
                    } else {
                        ASSERT(!!libc_pme, "failed to find glibc /proc/pid/maps entry for breakpoint \"%s\"", cur_ubp->name)
                        cur_ubpa->symbol_name = 0;
                        cur_ubpa->address = libc_pme->base;
                    }
                } else if (!strcmp(cur_ubpa->symbol_name, "bin") || !strcmp(cur_ubpa->symbol_name, "binary") || !strcmp(cur_ubpa->symbol_name, "target")) {
                    cur_ubpa->symbol_name = 0;
                    cur_ubpa->address = bin_pme->base;
                }
            }
        }
        cur_ubpa = cur_ubpa->next_operation;
    }

    // now, evaluate it
    if (cur_ubp->address) {
        cur_ubp->address_eval = _evaluate_user_breakpoint_address(cur_ubp);
    }
}


void fill_symbol_references(HeaptraceContext *ctx) {
    ProcMapsEntry *bin_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_BINARY);
    ProcMapsEntry *libc_pme = pme_walk(ctx->pme_head, PROCELF_TYPE_LIBC);
    ASSERT(bin_pme, "cannot find binary base address");

    UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
    while (cur_ubp) {
        UserBreakpoint *cur_ubp_nr = cur_ubp;
        while (cur_ubp_nr) {
            _fill_symbol_references(ctx, bin_pme, libc_pme, cur_ubp_nr);
            cur_ubp_nr = cur_ubp_nr->next_requirement;
        }
        cur_ubp = cur_ubp->next;
    }

    install_user_breakpoints(ctx);
}


static inline uint _check_breakpoint_logic(HeaptraceContext *ctx, UserBreakpoint *ubp) {
    if (ubp->what == UBP_WHAT_OID) {
        if (ubp->when != ctx->h_when) return 0;
        return ctx->h_oid == ubp->oid;
    } else if (ubp->what == UBP_WHAT_SEGFAULT) return ctx->h_state == PROCESS_STATE_SEGFAULT;
    else if (ubp->what == UBP_WHAT_ENTRY) return ctx->h_state == PROCESS_STATE_ENTRY;
    else {
        if (UBP_WHEN_CUSTOM_BP == ctx->h_when) return 0;
        return ubp->address_eval && ubp->address_eval == ctx->h_rip - 1;
    }
    return 0;
}


void check_should_break(HeaptraceContext *ctx) {
    UserBreakpoint *cur_ubp = USER_BREAKPOINT_HEAD;
    while (cur_ubp) {
        UserBreakpoint *cur_ubp_nr = cur_ubp; // next requirements list
        uint should_break = !!cur_ubp_nr;
        while (cur_ubp_nr) {
            if (_check_breakpoint_logic(ctx, cur_ubp_nr)) {
                debug("user breakpoint \"%s\" evaluated to true. rip=" U64T ", h_when=%d, i/count=%zu/%zu\n", cur_ubp_nr->name, ctx->h_rip, ctx->h_when, cur_ubp_nr->h_i + 1, cur_ubp_nr->count);
                if (!(++(cur_ubp_nr->h_i) >= cur_ubp_nr->count)) {
                    should_break = 0;
                }
            } else should_break = 0;
            cur_ubp_nr = cur_ubp_nr->next_requirement;
        }
        
        if (should_break) {
            // ok, we've hit this breakpoint enough to call gdb!
            log(COLOR_ERROR "\n    [   PROCESS PAUSED   ]\n");
            log(COLOR_ERROR "    |   * attaching GDB via: " COLOR_ERROR_BOLD "%s -p %d\n" COLOR_RESET, OPT_GDB_PATH, ctx->pid);

            // launch gdb
            _remove_breakpoints(ctx, BREAKPOINT_OPTS_ALL); // TODO/XXX: use end_debugger
            PTRACE(PTRACE_DETACH, ctx->pid, NULL, SIGSTOP);

            char buf[10+1];
            snprintf(buf, 10, "%u", ctx->pid);
            char *args[] = {OPT_GDB_PATH, "-p", buf, NULL};
            if (execv(args[0], args) == -1) {
                ASSERT(0, "failed to execute debugger %s: %s (errno %d)", args[0], strerror(errno), errno);
            }
        }
        cur_ubp = cur_ubp->next;
    }
}


