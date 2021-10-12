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

#include "chunk.h"

#define STATE_UNUSED 0
#define STATE_MALLOC 1
#define STATE_FREE 2
#define STATE_REALLOC 3

#define SIZE_SZ 8 // XXX
#define MALLOC_ALIGN_MASK (2*SIZE_SZ-1)
#define MIN_CHUNK_SIZE (SIZE_SZ*4) // this is not always true
#define MINSIZE (unsigned long)(((MIN_CHUNK_SIZE+MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK))
#define CHUNK_SIZE(req) ((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE ? MINSIZE : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & (~MALLOC_ALIGN_MASK)) // AKA request2size in malloc.c

//static uint64_t MALLOC_COUNT = 0, FREE_COUNT = 0, REALLOC_COUNT = 0;
extern uint64_t MALLOC_COUNT;
extern uint64_t CALLOC_COUNT;
extern uint64_t FREE_COUNT;
extern uint64_t REALLOC_COUNT;
extern uint64_t REALLOCARRAY_COUNT;

#define MAX_META_SIZE 8*8388600 // 64 MB
#define MAX_CHUNKS MAX_META_SIZE / sizeof(Chunk)

static int chunks_initialized;

void chunk_init();

#define MAX_BREAK_ATS 0xff
extern uint64_t break_ats[MAX_BREAK_ATS];

void check_oid(uint64_t oid, int prepend_newline);
uint64_t get_oid();
void show_stats();
