#ifndef CHUNK_H
#define CHUNK_H

#include "logging.h"

typedef struct HeaptraceContext HeaptraceContext;

typedef struct Chunk {
    int state;
    uint64_t ptr;
    uint64_t size;
    uint64_t ops[4]; // for tracking where ops happened: [placeholder for STATE_UNUSED, STATE_MALLOC oid, STATE_FREE oid, STATE_REALLOC oid]

    struct Chunk *left;
    struct Chunk *right;
} Chunk;


Chunk *alloc_chunk(HeaptraceContext *ctx, uint64_t ptr);
Chunk *find_chunk(HeaptraceContext *ctx, uint64_t ptr); // TODO: deprecate this function

#endif
