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

#include "util.h"
#include "proc.h"
#include "context.h"

void pre_malloc(HeaptraceContext *ctx, uint64_t isize);
void post_malloc(HeaptraceContext *ctx, uint64_t ptr);
void pre_calloc(HeaptraceContext *ctx, uint64_t nmemb, uint64_t isize);
void post_calloc(HeaptraceContext *ctx, uint64_t ptr);
void pre_free(HeaptraceContext *ctx, uint64_t iptr);
void post_free(HeaptraceContext *ctx, uint64_t retval);
void pre_realloc(HeaptraceContext *ctx, uint64_t iptr, uint64_t isize);
void post_realloc(HeaptraceContext *ctx, uint64_t new_ptr);
void pre_reallocarray(HeaptraceContext *ctx, uint64_t iptr, uint64_t nmemb, uint64_t isize);
void post_reallocarray(HeaptraceContext *ctx, uint64_t new_ptr);

