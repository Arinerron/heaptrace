#include "chunk.h"

Chunk *bst_root;
static void *_chunk_arr = 0;
static size_t _chunk_arr_i = 0;
static size_t _chunk_arr_sz = 1000;


static Chunk *_create_chunk() {
    // alloc a new block
    if (_chunk_arr_i == _chunk_arr_sz || !_chunk_arr) {
        _chunk_arr_i = 0;
        _chunk_arr = calloc(_chunk_arr_sz, sizeof(Chunk));
        if (!_chunk_arr) {
            fatal("_create_chunk: calloc out of memory");
        }
    }

    Chunk *chunk = (Chunk *)(_chunk_arr + (_chunk_arr_i * sizeof(Chunk)));
    _chunk_arr_i++;
    return chunk;
}


/*
 * walks the BST to find the ptr specified. If it is not found, and set_chunk 
 * is nonzero, it inserts the chunk and returns a pointer to new Chunk it  
 * inserted it at. Otherwise, it returns 0 indicating the Chunk was not found
 * 
 */
static Chunk *_find_chunk(Chunk *root, uint64_t ptr, Chunk *set_chunk) {
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


Chunk *alloc_chunk(uint64_t ptr) {
    Chunk *old_chunk = find_chunk(ptr);
    if (old_chunk) return old_chunk;

    // couldn't find it, create new one
    Chunk *new_chunk = _create_chunk();
    new_chunk->ptr = ptr;

    if (!bst_root) {
        bst_root = new_chunk;
        return new_chunk;
    } else {
        _find_chunk(bst_root, ptr, new_chunk);
    }
}


Chunk *find_chunk(uint64_t ptr) {
    if (!ptr) return 0;
    if (!bst_root) return 0;
    return _find_chunk(bst_root, ptr, 0);
}
