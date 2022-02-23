#include <sys/ioctl.h>
#include <stdarg.h>

#include "logging.h"
#include "context.h"
#include "heap.h"

FILE *output_fd;
int OPT_DEBUG = 0;
int OPT_VERBOSE = 0;
int OPT_NO_COLOR = 0;
size_t OPT_TERM_WIDTH = 0;

#define MIN_TERM_WIDTH 40
static size_t TERM_WIDTH = MIN_TERM_WIDTH;

static char *spaces_ptr = 0;


static inline void update_terminal_width() {
    if (OPT_TERM_WIDTH) {
        TERM_WIDTH = OPT_TERM_WIDTH;
        return;
    }

    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    size_t max_width = w.ws_col;
    if (max_width < MIN_TERM_WIDTH) max_width = MIN_TERM_WIDTH;
    else if (max_width > 400) max_width = 400;
    TERM_WIDTH = max_width;
}


static char *repeat_char(size_t num, char c) {
    spaces_ptr = realloc(spaces_ptr, num + 2);
    ASSERT(spaces_ptr, "Failed to realloc spaces_ptr. num=lu=%lu (ld=%ld), TERM_WIDTH=%zu. Please report this.", num, num, TERM_WIDTH);
    memset(spaces_ptr, c, num);
    spaces_ptr[num] = 0;

    return spaces_ptr;
}


void print_header_bars(char *msg, size_t msg_sz) {
    update_terminal_width();

    color_log(COLOR_LOG);
    if (msg && msg_sz && !(2 + msg_sz > TERM_WIDTH)) {
        size_t num_equals = (TERM_WIDTH - (2 + msg_sz)) / 2;
        char *rc = repeat_char(num_equals, '=');
        if (log("%s %s %s", rc, msg, rc) == TERM_WIDTH - 1) log("=");
        log("\n");
    } else {
        char *rc = repeat_char(TERM_WIDTH, '=');
        log("%s\n", rc);
    }
    color_log(COLOR_RESET);
}


void reset_handler_log_message(HeaptraceContext *ctx) {
    HandlerLogMessage *hlm = &(ctx->hlm);
    char *warnings = hlm->warnings;
    memset(hlm, 0, sizeof(HandlerLogMessage));
    hlm->warnings = warnings;
    memset(hlm->warnings, 0, HLM_WARNINGS_SIZE + 1);
}


static inline size_t print_arg(HeaptraceContext *ctx, uint options, uint64_t ptr) {
    size_t cur_width = 0;
    if (options & HLM_OPTION_SIZE) {
        color_log(COLOR_LOG_BOLD);
        cur_width += log("0x%02lx", ptr);
        color_log(COLOR_LOG);
    } else if (options & HLM_OPTION_ADDRESS) {
        color_log(COLOR_LOG_BOLD);
        cur_width += log(U64T, ptr);
        color_log(COLOR_LOG);
    } else if (options & HLM_OPTION_SYMBOL) {
        Chunk *chunk = find_chunk(ctx, ptr);
        if (chunk && chunk->ops[STATE_MALLOC]) {
            color_log(COLOR_SYMBOL_BOLD);
            cur_width += log("#");
            color_log(COLOR_SYMBOL);
            cur_width += log("%lu", chunk->ops[STATE_MALLOC]);
            color_log(COLOR_LOG);

            HandlerLogMessageNote *note = insert_note(ctx);
            concat_note_color(note, COLOR_SYMBOL_ITALIC);
            concat_note(note, "#%lu", chunk->ops[STATE_MALLOC]);
            concat_note_color(note, COLOR_LOG_ITALIC);
            concat_note(note, "=" U64T, PTR_ARG(ptr));
            concat_note_color(note, COLOR_LOG);
        } else {
            color_log(COLOR_LOG_BOLD);
            cur_width += log(U64T, ptr);
            color_log(COLOR_LOG);
        }
    } else {
        fatal("unknown print_arg option: %d for ptr " U64T ". Please report this!", options, ptr);
        abort();
    }
    return cur_width;
}


// prints the symbol being called
void print_handler_log_message_1(HeaptraceContext *ctx) {
    if (!ctx->hlm.func_name) return;

    update_terminal_width();

    size_t cur_width = 0;
    color_log(COLOR_LOG);
    cur_width += log("... ");
    color_log(COLOR_RESET);

    // SYM
    color_log(COLOR_SYMBOL_BOLD);
    cur_width += log("#");
    color_log(COLOR_SYMBOL);
    cur_width += log("%lu", ctx->h_oid + 1); // + 1 because this code runs before setting the new oid #
    color_log(COLOR_LOG);

    cur_width += log(": %s(", ctx->hlm.func_name);
    
    // print args
    for (int i = 0; i < 3; i++) {
        uint options = ctx->hlm.arg_options[i];
        if (options) {
            uint64_t ptr = ctx->hlm.arg_ptr[i];
            cur_width += print_arg(ctx, options, ptr);
            if (i + 1 < 3 && ctx->hlm.arg_options[i + 1]) cur_width += log(", ");
        }
    }

    cur_width += log(") ");
    color_log(COLOR_ERROR_BOLD);
    ctx->hlm.cur_width = cur_width;
}


#define MAX_NOTE_SIZE 200


HandlerLogMessageNote *insert_note(HeaptraceContext *ctx) {
    char *ptr = (char *)calloc(1, MAX_NOTE_SIZE + 2);

    HandlerLogMessageNote *note = (HandlerLogMessageNote *)calloc(1, sizeof(HandlerLogMessageNote));
    note->ptr = ptr;

    // insert in reverse order (FIFO)
    HandlerLogMessageNote *cur_note = ctx->hlm.notes_head;
    if (!cur_note) ctx->hlm.notes_head = note;
    else {
        while (cur_note->next) cur_note = cur_note->next;
        cur_note->next = note;
    }

    return note;
}


void free_hlm_notes_head(HeaptraceContext *ctx) {
    HandlerLogMessageNote *cur_note = ctx->hlm.notes_head;
    HandlerLogMessageNote *_tmp_note;
    while (cur_note) {
        _tmp_note = cur_note->next;
        free(cur_note);
        cur_note = _tmp_note;
    }
    ctx->hlm.notes_head = 0;
}


void concat_note(HandlerLogMessageNote *note, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    note->cur_width += vsnprintf(note->ptr + (note->cur_width + note->cur_width_color), MAX_NOTE_SIZE - (note->cur_width + note->cur_width_color), fmt, args);
    va_end(args);
}


void concat_note_color(HandlerLogMessageNote *note, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (!OPT_NO_COLOR) {
        size_t cur_size = note->cur_width + note->cur_width_color;
        note->cur_width_color += vsnprintf(note->ptr + cur_size, MAX_NOTE_SIZE - cur_size, fmt, args);
    }
    va_end(args);
}


inline static size_t calc_spaces_for_right_align(size_t cur_width, size_t text_sz) {
    size_t max_width = TERM_WIDTH;
    if (max_width > 200) {
        max_width = (max_width * 2) / 3;
    }

    if (text_sz >= max_width) {
        return 0; // nothing we can do if it's too long
    } else if (cur_width + text_sz >= max_width * 2) {
        return 0;
    } else if (cur_width + text_sz > max_width && cur_width + text_sz < max_width * 2) {
        return max_width - cur_width + max_width - text_sz; // if overflow, newline worth of spaces THEN right align
    } else {
        return max_width - (cur_width + text_sz);
    }
}


inline static size_t calc_spaces_for_position(size_t cur_width, size_t pos) {
    if (cur_width > pos) {
        if (cur_width > TERM_WIDTH) return 0;
        return TERM_WIDTH - cur_width + pos;
    } else return pos - cur_width;
}


// prints return value, the "notes", etc
void print_handler_log_message_2(HeaptraceContext *ctx) {
    size_t cur_width = ctx->hlm.cur_width;

    if (ctx->hlm.ret_options) {
        color_log(COLOR_LOG);
        
        size_t _mult = 5;
        if (TERM_WIDTH < 80) _mult = 7;
        else if (TERM_WIDTH >= 180) _mult = 3;
        cur_width += log("%s= ", repeat_char(calc_spaces_for_position(cur_width, (_mult * TERM_WIDTH) / 12), ' '));
        
        color_log(COLOR_LOG_BOLD);
        cur_width += log(U64T " ", ctx->hlm.ret_ptr);
        color_log(COLOR_LOG);
    }

    // calculate length of all notes (not including colors)
    HandlerLogMessageNote *cur_note = ctx->hlm.notes_head;
    size_t total_sz = 0;
    size_t num_notes = 0;
    while (cur_note) {
        total_sz += cur_note->cur_width;
        num_notes++;
        cur_note = cur_note->next;
    }

    cur_note = ctx->hlm.notes_head;
    if (cur_note) {
        // calculate size with parentheses etc
        total_sz += 2; // parentheses
        total_sz += 1; // space at the end
        total_sz += 2 * (num_notes - 1); // ", ". num_notes is always >= 1 here

        ctx->hlm.cur_width = cur_width;
        cur_width += log("%s", repeat_char(calc_spaces_for_right_align(cur_width, total_sz), ' '));
        color_log(COLOR_LOG);
        cur_width += log("(");

        // now print everything
        HandlerLogMessageNote *next_note;
        while (cur_note) {
            // free as we read
            next_note = cur_note->next;
            cur_width += log("%s", cur_note->ptr);
            if (next_note) {
                color_log(COLOR_LOG);
                cur_width += log(", ");
            }

            free(cur_note);
            cur_note = next_note;
        }
        ctx->hlm.notes_head = 0;

        color_log(COLOR_LOG);
        cur_width += log(")");
    }

    cur_width += log("\n");

    ctx->hlm.cur_width = cur_width;
}


// TODO: convert to elf parsing
/*void describe_symbol(void *ptr) {
    Dl_info ptrinfo;
    if (!OPT_VERBOSE) return;
    dladdr(ptr, &ptrinfo);

    if (ptrinfo.dli_sname && ptrinfo.dli_fname) {
        // symbol found
        log("\t(%s%s%s in %s%s%s)", BOLD(ptrinfo.dli_sname), BOLD(ptrinfo.dli_fname));
    }
}
*/
