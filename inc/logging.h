#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

extern int OPT_DEBUG; // print lots of debug info?
extern int OPT_VERBOSE;
extern int OPT_NO_COLOR;
extern size_t OPT_TERM_WIDTH;

#define COLOR_LOG "\e[0;36m"
#define COLOR_LOG_BOLD "\e[1;36m"
#define COLOR_LOG_ITALIC "\e[3;36m"
#define COLOR_SYMBOL "\e[0;35m"
#define COLOR_SYMBOL_BOLD "\e[1;35m"
#define COLOR_SYMBOL_ITALIC "\e[3;35m"
#define COLOR_ERROR "\e[0;31m"
#define COLOR_ERROR_BOLD "\e[1;31m"
#define COLOR_WARN "\e[0;93m"
#define COLOR_WARN_BOLD "\e[1;93m"
#define COLOR_RESET "\e[0m"
#define COLOR_RESET_ITALIC "\e[3m"
#define COLOR_RESET_BOLD "\e[1m"

extern FILE *output_fd;

#define color_log(...) { if (!OPT_NO_COLOR) { fprintf(output_fd, ##__VA_ARGS__); } }
#define color_verbose(...) { if (!OPT_NO_COLOR && OPT_VERBOSE) { fprintf(output_fd, ##__VA_ARGS__); } }

#define log(fmt, ...) fprintf(output_fd, (fmt), ##__VA_ARGS__) // XXX: ansi colors to file?
#define info(fmt, ...) { color_log(COLOR_LOG); fprintf(output_fd, (fmt), ##__VA_ARGS__); color_log(COLOR_RESET); } // XXX: ansi colors to file?
#define debug(fmt, ...) {if (OPT_DEBUG) { color_log(COLOR_RESET); log("[ ] "); color_log(COLOR_RESET_ITALIC); fprintf(output_fd, (fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }}
#define debug2(fmt, ...) {if (OPT_DEBUG) { color_log(COLOR_RESET COLOR_RESET_ITALIC); fprintf(output_fd, (fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }}
#define verbose(fmt, ...) {if (OPT_VERBOSE) { fprintf(output_fd, (fmt), ##__VA_ARGS__); }}
#define warn(fmt, ...) { color_log(COLOR_WARN_BOLD); log("heaptrace warning: "); color_log(COLOR_WARN); fprintf(output_fd, (fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define warn2(f_, fmt, ...) { color_log(COLOR_WARN_BOLD); log("heaptrace warning: "); color_log(COLOR_WARN); fprintf((f_), (fmt COLOR_RESET), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define error(fmt, ...) { color_log(COLOR_ERROR); fprintf(output_fd, ("heaptrace error: " fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define error2(f_, fmt, ...) { color_log(COLOR_ERROR); fprintf((f_), ("heaptrace error: " fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define fatal(fmt, ...) { color_log(COLOR_ERROR_BOLD); fprintf(output_fd, ("heaptrace error: " fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define fatal2(f_, fmt, ...) { color_log(COLOR_ERROR_BOLD); fprintf((f_), ("heaptrace error: " fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }

#define U64T "0x%" PRIx64

#define SYM COLOR_SYMBOL_BOLD "#" COLOR_SYMBOL "%lu" COLOR_LOG
#define SYM_IT COLOR_SYMBOL_ITALIC "#%lu" COLOR_LOG
#define SZ COLOR_LOG_BOLD "0x%02lx" COLOR_LOG
#define SZ_ERR COLOR_ERROR_BOLD "0x%02lx" COLOR_ERROR
#define SZ_ARG(sz) ((long unsigned int)(sz))
#define CNT COLOR_LOG_BOLD "%lu" COLOR_LOG
#define PTR COLOR_LOG_BOLD U64T COLOR_LOG
#define PTR_ERR COLOR_ERROR_BOLD U64T COLOR_ERROR
#define PTR_IT COLOR_LOG_ITALIC U64T COLOR_LOG
#define PTR_ARG(ptr) ((long unsigned int)(ptr))

#define log_heap(fmt, ...) { color_log(COLOR_LOG); fprintf(output_fd, (fmt), ##__VA_ARGS__); color_log(COLOR_RESET); }
#define verbose_heap(fmt, ...) { if (OPT_VERBOSE) { color_log(COLOR_LOG); log("\t^-- "); color_log(COLOR_LOG_ITALIC); fprintf(output_fd, (fmt "\n"), ##__VA_ARGS__);  color_log(COLOR_RESET); } }
#define fatal_heap(msg, ...) { color_log(COLOR_ERROR_BOLD); log("\nheaptrace error: "); color_log(COLOR_ERROR); log(msg "\n", ##__VA_ARGS__); color_log(COLOR_RESET); }
//#define warn2(msg) log("%sheaptrace warning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR, (msg), COLOR_RESET) 
#define warn_heap(msg, ...) { color_log(COLOR_WARN); ctx->hlm.cur_width = 0; log("\n    |-- warning: "); color_log(COLOR_WARN_BOLD); log(msg, ##__VA_ARGS__); color_log(COLOR_RESET); }
#define warn_heap2(msg, ...) { color_log(COLOR_WARN); log("    |   * " msg,  ##__VA_ARGS__); color_log(COLOR_RESET); }

#define log_sym(sym) { color_log(COLOR_SYMBOL_BOLD); log("#"); color_log(COLOR_SYMBOL); log("%lu", (sym)); color_log(COLOR_LOG); }

void describe_symbol(void *ptr);

#ifndef LOGGING_H
#define LOGGING_H

typedef struct HeaptraceContext HeaptraceContext;

typedef struct HandlerLogMessageNote {
    char *ptr;
    size_t cur_width;
    uint64_t cur_width_color;

    struct HandlerLogMessageNote *next;
} HandlerLogMessageNote;

// TODO: #53: finish this
#define HLM_OPTION_SYMBOL 2 // falls back to address
#define HLM_OPTION_ADDRESS 4
#define HLM_OPTION_SIZE 8

#define HLM_WARNINGS_SIZE 4096
typedef struct HandlerLogMessage {
    // handler variables

    char *func_name;
    char *warnings; // malloced and zero'd every operation

    uint arg_options[3];
    uint64_t arg_ptr[3];

    uint ret_options;
    uint64_t ret_ptr;

    // msgs
    HandlerLogMessageNote *notes_head;

    // debugger variables

    uint64_t cur_width;
} HandlerLogMessage;

void reset_handler_log_message(HeaptraceContext *ctx);
void print_handler_log_message_1(HeaptraceContext *ctx);
void print_handler_log_message_2(HeaptraceContext *ctx);

HandlerLogMessageNote *insert_note(HeaptraceContext *ctx);
void free_hlm_notes_head(HeaptraceContext *ctx);
void concat_note(HandlerLogMessageNote *note, const char *fmt, ...);
void concat_note_color(HandlerLogMessageNote *note, const char *fmt, ...);

void print_header_bars(char *msg, size_t msg_sz);

#endif
