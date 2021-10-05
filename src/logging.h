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

#include "options.h"

#define COLOR_LOG "\e[0;36m"
#define COLOR_LOG_BOLD "\e[1;36m"
#define COLOR_LOG_ITALIC "\e[3;36m"
#define COLOR_SYMBOL "\e[0;35m"
#define COLOR_SYMBOL_BOLD "\e[1;35m"
#define COLOR_ERROR "\e[0;31m"
#define COLOR_ERROR_BOLD "\e[1;31m"
#define COLOR_RESET "\e[0m"

static FILE *output_fd;

#define log(f_, ...) { fprintf(stderr, (f_), ##__VA_ARGS__); } // XXX: ansi colors to file?
#define warn2(f_, ...) { fprintf(stderr, (f_), ##__VA_ARGS__); } // TODO: color and prefix?

#define BOLD(msg) COLOR_LOG_BOLD, (msg), COLOR_LOG // %s%d%s
#define BOLD_SYMBOL(msg) COLOR_SYMBOL_BOLD, (msg), COLOR_LOG // %s%d%s
#define BOLD_ERROR(msg) COLOR_ERROR_BOLD, (msg), COLOR_ERROR // %s%d%s
#define error(msg) log("%sheaptrace error: %s%s%s\n", COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET) 
//#define warn2(msg) log("%sheaptrace warning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR, (msg), COLOR_RESET) 
#define warn(msg) log("%s    |-- %swarning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET)

#define ASSERT(q, msg) if (!(q)) { error(msg); abort(); }

void describe_symbol(void *ptr);
