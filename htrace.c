#define _GNU_SOURCE
#include <malloc.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>

#define log(f_, ...) fprintf(stderr, (f_), ##__VA_ARGS__)

void *(*orig_malloc)(size_t size);
void (*orig_free)(void *ptr);
 
void *malloc(size_t size) {
    log("... malloc(0x%02lx)\t", size);
    void *ptr = orig_malloc(size);
    log(" = 0x%llx\n", (long long unsigned int)ptr);
    return ptr;
}

void free(void *ptr) {
    log("... free(0x%llx)\n", (long long unsigned int)ptr);
    orig_free(ptr);
}
 
void _init(void) {
    if (!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!orig_free) orig_free = dlsym(RTLD_NEXT, "free");
    log("Initialized heaptrace.\n");
}
