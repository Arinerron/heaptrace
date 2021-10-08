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

#define log(f_, ...) { fprintf(output_fd, (f_), ##__VA_ARGS__); } // XXX: ansi colors to file?
#define debug(fmt, ...) {if (OPT_DEBUG) { fprintf(output_fd, ("[ ] " COLOR_RESET_ITALIC fmt COLOR_RESET), ##__VA_ARGS__); }}
#define verbose(fmt, ...) {if (OPT_VERBOSE) { fprintf(output_fd, (fmt), ##__VA_ARGS__); }}
#define warn(fmt, ...) { fprintf(output_fd, (COLOR_WARN_BOLD "heaptrace warning: " COLOR_WARN fmt COLOR_RESET), ##__VA_ARGS__); }
#define warn2(f_, fmt, ...) { fprintf((f_), (COLOR_WARN_BOLD "heaptrace warning: " COLOR_WARN fmt COLOR_RESET), ##__VA_ARGS__); }
#define error(fmt, ...) { fprintf(output_fd, (COLOR_ERROR "heaptrace error: " fmt COLOR_RESET), ##__VA_ARGS__); }
#define error2(f_, fmt, ...) { fprintf((f_), (COLOR_ERROR "heaptrace error: " fmt COLOR_RESET), ##__VA_ARGS__); }
#define fatal(fmt, ...) { fprintf(output_fd, (COLOR_ERROR_BOLD "heaptrace error: " fmt COLOR_RESET), ##__VA_ARGS__); }
#define fatal2(f_, fmt, ...) { fprintf((f_), (COLOR_ERROR_BOLD "heaptrace error: " fmt COLOR_RESET), ##__VA_ARGS__); }

#define SYM COLOR_SYMBOL_BOLD "#" COLOR_SYMBOL "%lu" COLOR_LOG
#define SYM_IT COLOR_SYMBOL_ITALIC "#%lu" COLOR_LOG
#define SZ COLOR_LOG_BOLD "0x%02lx" COLOR_LOG
#define SZ_ERR COLOR_ERROR_BOLD "0x%02lx" COLOR_ERROR
#define SZ_ARG(sz) ((long unsigned int)(sz))
#define CNT COLOR_LOG_BOLD "%lu" COLOR_LOG
#define PTR COLOR_LOG_BOLD "0x%llx" COLOR_LOG
#define PTR_IT COLOR_LOG_ITALIC "0x%llx" COLOR_LOG
#define PTR_ARG(ptr) ((long long unsigned int)(ptr))

#define log_heap(fmt, ...) { fprintf(output_fd, (COLOR_LOG fmt COLOR_RESET), ##__VA_ARGS__); }
#define fatal_heap(msg, ...) log(COLOR_ERROR_BOLD, "heaptrace error: " COLOR_ERROR msg COLOR_RESET "\n", ##__VA_ARGS__)
//#define warn2(msg) log("%sheaptrace warning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR, (msg), COLOR_RESET) 
#define warn_heap(msg) log("%s    |-- %swarning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET)
#define warn_heap2(msg, ...) log(COLOR_ERROR "    |   * " msg "\n" COLOR_RESET,  ##__VA_ARGS__)

#define ASSERT(q, msg, ...) if (!(q)) { fatal_heap(msg, #__VA_ARGS__); abort(); }

void describe_symbol(void *ptr);
