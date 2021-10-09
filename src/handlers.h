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

static int caused_by_heapalloc = 0; //  TODO: remove

void pre_malloc(uint64_t isize);
void post_malloc(uint64_t ptr);
void pre_calloc(uint64_t nmemb, uint64_t isize);
void post_calloc(uint64_t ptr);
void pre_free(uint64_t iptr);
void post_free(uint64_t retval);
void pre_realloc(uint64_t iptr, uint64_t isize);
void post_realloc(uint64_t new_ptr);
