#include "logging.h"
#include "util.h"
#include "user-breakpoint.h"


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
            if (c == ' ' || c == '\t' || c == '\n') {
                // skip whitespace
                continue;
            } else {
                // start token
                start_ptr = s;
                in_token = 1;
            }
        }

        if (start_ptr != s) { // if in the middle of a token
            if (c == ':' || c == '+' || c == '-' || c == '=' || c == '\0' || c == ' ' || c == '\t' || c == '\n') {
                next_token = _create_token(start_ptr, s - start_ptr, UBPT_TYPE_IDENTIFIER, i - (s - start_ptr));
                if (!token_head) token_head = next_token;
                if (cur_token) cur_token->next = next_token;
                cur_token = next_token;
                start_ptr = s;
                in_token = 0;
            }
        }

        if (!in_token) {
            if (c == ':' || c == '+' || c == '-' || c == '=') {
                cur_token = _create_token(start_ptr, 1, UBPT_TYPE_PUNCTUATOR, i - (s - start_ptr));
                if (!token_head) token_head = cur_token;
                if (cur_token) cur_token->next = next_token;
                cur_token = next_token;
                in_token = 0;
            }
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
        exit(1);
    }
}


UserBreakpoint *create_user_breakpoint(char *name) {
    UserBreakpointToken *token_head = tokenize_user_breakpoint_str(name);
    UserBreakpoint *ubp = (UserBreakpoint *)calloc(1, sizeof(UserBreakpoint));
    ubp->name = strdup(name);
    ubp->when = UBP_WHEN_BEFORE;
    
    UserBreakpointToken *cur_token = token_head;
    #define EXPECT(b, msg) _expect_token(ubp, cur_token, (b), (msg))
    #define GET() EXPECT(cur_token && cur_token->next, "expected a token following this one"); cur_token = cur_token->next;
    enum action {ACTION_WHAT, ACTION_ADDRESS, ACTION_COUNT} cur_action = ACTION_WHAT;
    while (cur_token) {
        printf("cur_token (%d): %s\n", cur_token->type, cur_token->value);
        EXPECT(cur_token->type == UBPT_TYPE_IDENTIFIER, "expected an identifier");
        if (cur_action == ACTION_WHAT) {
            if (!strcmp(cur_token->value, "address") || !strcmp(cur_token->value, "addr")) {
                ubp->what = UBP_WHAT_ADDRESS;
                printf("next: %p\n", cur_token->next);
                GET();
            } else if (!strcmp(cur_token->value, "oid") || !strcmp(cur_token->value, "operation") || !strcmp(cur_token->value, "number")) {
                ubp->what = UBP_WHAT_OID;
                GET();
            } else if (!strcmp(cur_token->value, "segfault") || !strcmp(cur_token->value, "sigsegv") || !strcmp(cur_token->value, "segv")) {
                ubp->what = UBP_WHAT_SEGFAULT;
            } else if (!strcmp(cur_token->value, "main") || !strcmp(cur_token->value, "entry") || !strcmp(cur_token->value, "start") || !strcmp(cur_token->value, "_entry")) {
                ubp->what = UBP_WHAT_ENTRY;
            } else {
                EXPECT(0, "unknown 'what': please choose one of [oid, address, segfault, entry]");
            }
        }
        break;
    }

    return ubp;
}


