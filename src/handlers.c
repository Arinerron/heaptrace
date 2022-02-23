#include "handlers.h"
#include "logging.h"
#include "heap.h"
#include "options.h"
#include "user-breakpoint.h"


static void PRINT_SOURCE(HeaptraceContext *ctx) {
    if (OPT_VERBOSE) {
        char *SRC_FUNC = get_source_function(ctx);
        HandlerLogMessageNote *note_src = insert_note(ctx);
        concat_note(note_src, "called by: ");
        concat_note_color(note_src, COLOR_LOG_BOLD);
        concat_note(note_src, "%s", SRC_FUNC);
        free(SRC_FUNC);

        HandlerLogMessageNote *note_ret = insert_note(ctx);
        concat_note(note_ret, "returns to 0x%lx", ctx->h_ret_ptr);
    }
}


// check if pointer is in stack, libc, or binary, and error if so
static void _check_heap_ptr_retval(HeaptraceContext *ctx, uint64_t ptr) {
    if (!ptr) return; // we already have NULL warnings
    ProcMapsEntry *pme = pme_find_addr(ctx->pme_head, ptr);
    if (pme) {
        if (pme->pet == PROCELF_TYPE_LIBC // possibly malloc hook?
                || pme->pet == PROCELF_TYPE_BINARY // possibly GOT?
                || pme->pet == PROCELF_TYPE_STACK) { // possibly return ptr?
            warn_heap("return value is not a heap pointer\n");
            warn_heap2("this indicates some form of heap corruption\n");
            warn_heap2("pointer is inside of section \"%s\" (" U64T "-" U64T ")\n", pme->name, pme->base, pme->end);
        }
    }
}


void pre_calloc(HeaptraceContext *ctx, uint64_t nmemb, uint64_t isize) {
    ctx->h_size = (size_t)isize * (size_t)nmemb;

    ctx->calloc_count++;
    ctx->h_oid = GET_OID();
}


void post_calloc(HeaptraceContext *ctx, uint64_t ptr) {
    PRINT_SOURCE(ctx);

    // store meta info
    Chunk *chunk = alloc_chunk(ctx, ptr);

    if (chunk->state == STATE_MALLOC) {
        warn_heap("calloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption\n");
        warn_heap2("first calloc'd in operation ");
        log_sym(chunk->ops[STATE_MALLOC]);
        log("\n");
    }

    if (!ptr && !ctx->h_size) {
        /* SEE MAN PAGE:
         * On error, these functions return NULL. NULL may also be returned 
         * by a successful call to malloc() with a size of zero, or by a 
         * successful call to calloc() with nmemb or size equal to zero.
         */
        warn_heap("NULL return value indicates that an error happened\n");
    } 

    _check_heap_ptr_retval(ctx, ptr);

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = ctx->h_size;
    chunk->ops[STATE_MALLOC] = ctx->h_oid;
    chunk->ops[STATE_FREE] = 0;
    chunk->ops[STATE_REALLOC] = 0;
}


void pre_malloc(HeaptraceContext *ctx, uint64_t isize) {
    ctx->h_size = (size_t)isize;
    ctx->malloc_count++;
    ctx->h_oid = GET_OID();
}


void post_malloc(HeaptraceContext *ctx, uint64_t ptr) {
    PRINT_SOURCE(ctx);

    // store meta info
    Chunk *chunk = alloc_chunk(ctx, ptr);

    if (chunk->state == STATE_MALLOC) {
        warn_heap("malloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption\n");
        warn_heap2("first allocated in operation ");
        log_sym(chunk->ops[STATE_MALLOC]);
        log("\n");
    }

    if (!ptr && !ctx->h_size) {
        /* SEE MAN PAGE:
         * On error, these functions return NULL. NULL may also be returned 
         * by a successful call to malloc() with a size of zero, or by a 
         * successful call to calloc() with nmemb or size equal to zero.
         */
        warn_heap("NULL return value indicates that an error happened\n");
    } 

    _check_heap_ptr_retval(ctx, ptr);

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = ctx->h_size;
    chunk->ops[STATE_MALLOC] = ctx->h_oid;
    chunk->ops[STATE_FREE] = 0;
    chunk->ops[STATE_REALLOC] = 0;
}


void pre_free(HeaptraceContext *ctx, uint64_t iptr) {
    ctx->h_ptr = iptr;
    ctx->free_count++;
    ctx->h_oid = GET_OID();

    Chunk *chunk = find_chunk(ctx, ctx->h_ptr);

    // find meta info, check to make sure it's all good
    if (!chunk) {
        if (ctx->h_ptr) {
            // NOTE: the if(ptr) is because NULL is explicitly allowed in man page as NOOP
            warn_heap("freeing a pointer to unknown chunk\n");
        }
    } else if (chunk->ptr != ctx->h_ptr) {
        warn_heap("freeing a pointer that is inside of a chunk\n");
        warn_heap2("container chunk malloc()'d in " SYM " @ " PTR " with size " SZ "\n", chunk->ops[STATE_MALLOC], PTR_ARG(chunk->ptr), SZ_ARG(chunk->size));
    } else if (chunk->state == STATE_FREE) {
        warn_heap("attempting to double free a chunk\n");
        warn_heap2("allocated in operation ");
        log_sym(chunk->ops[STATE_MALLOC]);
        log("\n");
        warn_heap2("first freed in operation ");
        log_sym(chunk->ops[STATE_FREE]);
        log("\n");
    } else {
        // all is good!
        ASSERT(chunk->state != STATE_UNUSED, "cannot free unused chunk");
        chunk->state = STATE_FREE;
        chunk->ops[STATE_FREE] = ctx->h_oid;
    }
}


void post_free(HeaptraceContext *ctx, uint64_t retval) {
    log(COLOR_RESET);
    PRINT_SOURCE(ctx);
}


// _type=1 means "realloc", _type=2 means "reallocarray"
void _pre_realloc(HeaptraceContext *ctx, int _type, uint64_t iptr, uint64_t nmemb, uint64_t isize) {
    char *_name = "realloc";
    if (_type == 2) _name = "reallocarray";

    ctx->h_ptr = iptr;
    ctx->h_size = isize * nmemb;
    if (_type == 1) ctx->realloc_count++; else if (_type == 2) ctx->reallocarray_count++;
    ctx->h_oid = GET_OID();

    ctx->h_orig_chunk = alloc_chunk(ctx, ctx->h_ptr);

    if (ctx->h_orig_chunk && ctx->h_orig_chunk->state == STATE_FREE) {
        warn_heap("attempting to %s a previously-freed chunk\n", _name);
        warn_heap2("allocated in operation ");
        log_sym(ctx->h_orig_chunk->ops[STATE_MALLOC]);
        log("\n");
        warn_heap2("freed in operation ");
        log_sym(ctx->h_orig_chunk->ops[STATE_FREE]);
        log("\n");
    } else if (ctx->h_ptr && !ctx->h_orig_chunk) {
        // ptr && because https://github.com/Arinerron/heaptrace/issues/9
        //   0x0 is a special value
        warn_heap("attempting to %s a chunk that was never allocated\n", _name);
    }
}


void pre_realloc(HeaptraceContext *ctx, uint64_t iptr, uint64_t isize) {
    _pre_realloc(ctx, 1, iptr, 1, isize);
}


void pre_reallocarray(HeaptraceContext *ctx, uint64_t iptr, uint64_t nmemb, uint64_t isize) {
    _pre_realloc(ctx, 2, iptr, nmemb, isize);
}


// _type=1 means "realloc", _type=2 means "reallocarray"
static inline void _post_realloc(HeaptraceContext *ctx, int _type, uint64_t new_ptr) {
    char *_name = "realloc";
    if (_type == 2) _name = "reallocarray";

    PRINT_SOURCE(ctx);
    //warn("this code is untested; please report any issues you come across @ https://github.com/Arinerron/heaptrace/issues/new/choose");

    Chunk *new_chunk = alloc_chunk(ctx, new_ptr);

    if (ctx->h_ptr == new_ptr) {
        // the chunk shrank
        
        //ASSERT_NICE(ctx->h_orig_chunk == new_chunk, "the new/old Chunk meta are not equiv (new=" PTR_ERR ", old=" PTR_ERR ")", PTR_ARG(new_chunk), PTR_ARG(ctx->h_orig_chunk));

        if (new_chunk) {
            new_chunk->ops[STATE_MALLOC] = ctx->h_oid; // NOTE: we treat it as a malloc for now
            new_chunk->ops[STATE_REALLOC] = ctx->h_oid;
            if (ctx->h_orig_chunk) {
                ctx->h_orig_chunk->size = ctx->h_size;
            } // the else condition is unnecessary because there's a check above for !ctx->h_orig_chunk
        }
    } else {
        int _override_free = 1; // this is because it doesn't free if reallocarray's size calc overflows
        if (new_ptr) {
            // the chunk moved
            new_chunk = alloc_chunk(ctx, new_ptr);
            if (new_chunk->state == STATE_MALLOC) {
                warn_heap("%s returned a pointer to a chunk that was never freed (but not the original chunk), which indicates some form of heap corruption\n", _name);
                warn_heap2("first allocated in operation ");
                log_sym(new_chunk->ops[STATE_MALLOC]);
                log("\n");
            }

            new_chunk->state = STATE_MALLOC;
            new_chunk->ptr = new_ptr;
            new_chunk->size = ctx->h_size;
            new_chunk->ops[STATE_MALLOC] = ctx->h_oid; // NOTE: I changed my mind. Treat it as a malloc.
            //new_chunk->ops[STATE_MALLOC] = (ptr ? ctx->h_orig_chunk->ops[STATE_MALLOC] : oid); // realloc can act as malloc() when ptr is 0
            new_chunk->ops[STATE_FREE] = 0;
            new_chunk->ops[STATE_REALLOC] = ctx->h_oid;

            // old chunk gets marked as free after this if block
        } else {
            if (_type == 2) { // reallocarray only
                /* FROM THE MAN PAGE:
                 * However, unlike that realloc() call, reallocarray() fails 
                 * safely in the case where the multiplication would overflow. 
                 * If such an overflow occurs, reallocarray() returns NULL, 
                 * sets errno to ENOMEM, and leaves the original block.
                 */
                if (ctx->h_size) {
                    warn_heap("%s returned NULL even though size was not 0, indicating an error\n", _name);
                    _override_free = 0; // this one case does NOT free
                } // else means it was freed; it returns NULL too. Leave this case alone.
            } else {
                ASSERT(!ctx->h_size, "realloc/reallocarray returned NULL even though size was not zero");
            }
        }
        
        _check_heap_ptr_retval(ctx, new_ptr);
        
        if (ctx->h_ptr && ctx->h_orig_chunk && _override_free) {
            ctx->h_orig_chunk->state = STATE_FREE;
            ctx->h_orig_chunk->ops[STATE_FREE] = ctx->h_oid;
        } // no need for else if (!ctx->h_orig_chunk) because !ctx->h_orig_chunk is above
    }
}

void post_realloc(HeaptraceContext *ctx, uint64_t new_ptr) {
    _post_realloc(ctx, 1, new_ptr);
}


void post_reallocarray(HeaptraceContext *ctx, uint64_t new_ptr) {
    _post_realloc(ctx, 2, new_ptr);
}
