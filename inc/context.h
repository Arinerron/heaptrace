#ifndef HCTX_H
#define HCTX_H

#include <stdint.h>
#include <stdlib.h>

#include "proc.h"
#include "chunk.h"

typedef struct Chunk Chunk;

typedef struct HeaptraceContext {
    // init settings
    char *target_path;
    char **target_argv;

    // pre-analysis settings
    char *target_interp_name;
    int target_is_stripped;
    int target_is_dynamic;
    
    // runtime settings
    uint pid;
    int status; // waitpid
    int status16; // waitpid >> 16

    // mid-analysis settings
    uint64_t target_at_entry; // auxiliary vector AT_ENTRY

    // post-analysis settings
    ProcMapsEntry *pme_head;
    char *libc_path;
    char *libc_version;

    // chunk storage globals
    Chunk *chunk_root;
    void *chunk_arr;
    size_t chunk_arr_i;
} HeaptraceContext;

void *free_ctx(HeaptraceContext *ctx);
HeaptraceContext *alloc_ctx();

#endif
