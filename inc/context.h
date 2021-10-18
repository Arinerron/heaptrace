#ifndef HCTX_H
#define HCTX_H

#include <stdint.h>
#include <stdlib.h>

#include "util.h"
#include "proc.h"
#include "chunk.h"
#include "breakpoint.h"

typedef struct HeaptraceFile HeaptraceFile;

#include "symbol.h"

typedef struct Chunk Chunk;
typedef struct SymbolEntry SymbolEntry;

typedef struct HeaptraceContext {
    // init settings
    char **target_argv;
    char **se_names;
    SymbolEntry *target_se_head;

    // pre-analysis settings
    HeaptraceFile *target;
    HeaptraceFile *libc;

    Breakpoint **pre_analysis_bps;
    Breakpoint *bp_entry;

    SymbolEntry *libc_se_head;
    
    // runtime settings
    uint pid;
    int status; // waitpid
    int status16; // waitpid >> 16
    int code; // (status >> 8) & 0xffff
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
    char *libc_version;

    // chunk storage globals
    Chunk *chunk_root;
    void *chunk_arr;
    size_t chunk_arr_i;

    // breakpoints storage globals
    Breakpoint *breakpoints[BREAKPOINTS_COUNT];
} HeaptraceContext;


typedef struct HeaptraceFile {
    HeaptraceContext *ctx;
    char *path;
    uint is_dynamic;
    uint is_stripped;
    SymbolEntry *se_head;
} HeaptraceFile;

void *free_ctx(HeaptraceContext *ctx);
HeaptraceContext *alloc_ctx();

#endif
