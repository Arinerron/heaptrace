#ifndef HCTX_H
#define HCTX_H

#include <stdint.h>
#include <stdlib.h>

#include "proc.h"
#include "chunk.h"
#include "breakpoint.h"
#include "symbol.h"

typedef struct Chunk Chunk;
typedef struct SymbolEntry SymbolEntry;

typedef struct HeaptraceContext {
    // init settings
    char *target_path;
    char **target_argv;
    char **se_names;
    SymbolEntry *target_se_head;

    // pre-analysis settings
    char *target_interp_name;
    uint target_is_stripped;
    uint target_is_dynamic;
    Breakpoint *bp_entry;

    SymbolEntry *libc_se_head;
    uint libc_is_stripped;
    
    // runtime settings
    uint pid;
    int status; // waitpid
    int status16; // waitpid >> 16
    uint should_map_syms;

    char *between_pre_and_post;
    ProcELFType ret_ptr_section_type;

    size_t h_size;
    uint64_t h_ptr;
    uint64_t h_oid;
    Chunk *h_orig_chunk;

    uint64_t malloc_count;
    uint64_t calloc_count;
    uint64_t free_count;
    uint64_t realloc_count;
    uint64_t reallocarray_count;

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

    // breakpoints storage globals
    Breakpoint *breakpoints[BREAKPOINTS_COUNT];
} HeaptraceContext;

void *free_ctx(HeaptraceContext *ctx);
HeaptraceContext *alloc_ctx();

#endif
