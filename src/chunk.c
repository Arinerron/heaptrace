#ifndef CHUNK_C
#define CHUNK_C

#include "chunk.h"
#include "heap.h"
#include "context.h"

static const size_t CHUNK_ARR_SZ = 1000;


static Chunk *_create_chunk(HeaptraceContext *ctx) {
    return (Chunk *)calloc(1, sizeof(Chunk) + 1);
    /*// alloc a new block if necessary
    if (ctx->chunk_arr_i == CHUNK_ARR_SZ || !ctx->chunk_arr) {
        ctx->chunk_arr_i = 0;
        ctx->chunk_arr = calloc(CHUNK_ARR_SZ, sizeof(Chunk));
        if (!CHUNK_ARR_SZ) {
            fatal("_create_chunk: calloc out of memory");
        }
    }

    Chunk *chunk = &(((Chunk *)ctx->chunk_arr)[ctx->chunk_arr_i++]);
    return chunk;*/
}


/*
 * walks the BST to find the ptr specified. If it is not found, and set_chunk 
 * is nonzero, it inserts the chunk and returns a pointer to new Chunk it  
 * inserted it at. Otherwise, it returns 0 indicating the Chunk was not found
 * 
 */
static Chunk *_find_chunk(Chunk *root, uint64_t ptr, Chunk *set_chunk) {
    if (!root) return 0;
    if (!set_chunk && root->ptr == ptr) return root;

    if (ptr <= root->ptr) {
        if (root->left) {
            return _find_chunk(root->left, ptr, set_chunk);
        } else {
            if (set_chunk) {
                root->left = set_chunk;
                return set_chunk;
            } else {
                return 0;
            }
        }
    } else { // ptr > root->ptr
        if (root->right) {
            return _find_chunk(root->right, ptr, set_chunk);
        } else {
            if (set_chunk) {
                root->right = set_chunk;
                return set_chunk;
            } else {
                return 0;
            }
        }
    }
}


Chunk *alloc_chunk(HeaptraceContext *ctx, uint64_t ptr) {
    Chunk *old_chunk = find_chunk(ctx, ptr);
    if (old_chunk) return old_chunk;

    // couldn't find it, create new one
    Chunk *new_chunk = _create_chunk(ctx);
    new_chunk->ptr = ptr;

    if (!ctx->chunk_root) {
        ctx->chunk_root = new_chunk;
        return new_chunk;
    } else {
        _find_chunk(ctx->chunk_root, ptr, new_chunk);
    }
}


Chunk *find_chunk(HeaptraceContext *ctx, uint64_t ptr) {
    if (!ptr) return 0;
    return _find_chunk(ctx->chunk_root, ptr, 0);
}


static void _free_chunk_tree(Chunk *chunk) {
    if (chunk->left) _free_chunk_tree(chunk->left);
    if (chunk->right) _free_chunk_tree(chunk->right);
    free(chunk);
}


void free_chunks(HeaptraceContext *ctx) {
    if (ctx->chunk_root) _free_chunk_tree(ctx->chunk_root);
    ctx->chunk_root = 0;
}


uint64_t count_unfreed_bytes(Chunk *chunk) {
    uint64_t nbytes = 0;
    if (chunk) {
        if (chunk->state == STATE_MALLOC) {
            nbytes += CHUNK_SIZE(chunk->size);
        }
        nbytes += count_unfreed_bytes(chunk->left);
        nbytes += count_unfreed_bytes(chunk->right);
    }
    return nbytes;
}

#endif
