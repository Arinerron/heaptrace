#define _GNU_SOURCE
#include <malloc.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>

#define log(f_, ...) fprintf(stderr, (f_), ##__VA_ARGS__)

#define COLOR_RED "\e[0;31m"
#define COLOR_RED_BOLD "\e[1;31m"
#define COLOR_RESET "\e[0m"

void *(*orig_malloc)(size_t size);
void (*orig_free)(void *ptr);
 
void *malloc(size_t size) {
    log("%s... malloc(%s0x%02lx%s)\t%s", COLOR_RED, COLOR_RED_BOLD, size, COLOR_RED, COLOR_RESET);
    void *ptr = orig_malloc(size);
    log("%s = %s0x%llx%s\n", COLOR_RED, COLOR_RED_BOLD, (long long unsigned int)ptr, COLOR_RESET);
    return ptr;
}

void free(void *ptr) {
    log("%s... free(%s0x%llx%s)%s\n", COLOR_RED, COLOR_RED_BOLD, (long long unsigned int)ptr, COLOR_RED, COLOR_RESET);
    orig_free(ptr);
}
 
void _init(void) {
    if (!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!orig_free) orig_free = dlsym(RTLD_NEXT, "free");
    log("%sInitialized heaptrace.%s\n", COLOR_RED, COLOR_RESET);
}
