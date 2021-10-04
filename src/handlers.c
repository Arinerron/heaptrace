#include "handlers.h"
#include "logging.h"
#include "heap.h"

static size_t size;
static uint64_t ptr;
static uint64_t oid;
static Chunk *orig_chunk;


void pre_malloc(uint64_t isize) {
    size = (size_t)isize;
    
    if (caused_by_heapalloc) return;

    MALLOC_COUNT++;
    oid = get_oid();

    log("%s... %s#%lu%s: malloc(%s0x%02lx%s)\t\t%s", COLOR_LOG, BOLD_SYMBOL(oid), BOLD(size), COLOR_RESET);
    check_oid(oid, 1); // see if it's time to pause
}


void post_malloc(uint64_t ptr) {
    if (caused_by_heapalloc) return;

    log("%s=  %s0x%llx%s%s\n", COLOR_LOG, BOLD((long long unsigned int)ptr), COLOR_RESET);

    // store meta info
    Chunk *chunk = alloc_chunk(ptr);

    if (chunk->state == STATE_MALLOC) {
        warn("malloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption");
        log("%s    |   * first malloc'd in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(chunk->ops[STATE_MALLOC]), COLOR_RESET);
    }

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = size;
    chunk->ops[STATE_MALLOC] = oid;
    chunk->ops[STATE_FREE] = 0;
    chunk->ops[STATE_REALLOC] = 0;
}


void pre_free(uint64_t iptr) {
    ptr = iptr;

    if (caused_by_heapalloc) return;

    FREE_COUNT++;
    uint64_t oid = get_oid();

    Chunk *chunk = find_chunk(ptr);

    log("%s... #%s%lu%s: free(", COLOR_LOG, BOLD(oid));
    if (chunk && chunk->ops[STATE_MALLOC]) {
        log("%s#%lu%s)\t\t   %s(%s#%lu%s%s=%s0x%llx%s%s)", BOLD_SYMBOL(chunk->ops[STATE_MALLOC]), COLOR_LOG_ITALIC, BOLD_SYMBOL(chunk->ops[STATE_MALLOC]), COLOR_LOG_ITALIC, BOLD((long long unsigned int)ptr), COLOR_LOG_ITALIC);
    } else {
        log("%s0x%llx%s)", BOLD((long long unsigned int)ptr));
    }
    //describe_symbol();
    log("%s\n", COLOR_RESET);

    // find meta info, check to make sure it's all good
    if (!chunk) {
        if (ptr) {
            // NOTE: the if(ptr) is because NULL is explicitly allowed in man page as NOOP
            warn("freeing a pointer to unknown chunk");
        }
    } else if (chunk->ptr != ptr) {
        warn("freeing a pointer that is inside of a chunk");
        log("%s    |   * container chunk malloc()'d in %s#%lu%s @ %s0x%llx%s with size %s0x%llx%s%s\n", COLOR_ERROR, BOLD_ERROR(chunk->ops[STATE_MALLOC]), BOLD_ERROR((long long unsigned int)chunk->ptr), BOLD_ERROR((long long unsigned int)chunk->size), COLOR_RESET);
    } else if (chunk->state == STATE_FREE) {
        warn("attempting to double free a chunk");
        log("%s    |   * malloc'd in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(chunk->ops[STATE_MALLOC]), COLOR_RESET);
        log("%s    |   * first freed in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(chunk->ops[STATE_FREE]), COLOR_RESET);
    } else {
        // all is good!
        ASSERT(chunk->state != STATE_UNUSED, "cannot free unused chunk");
        chunk->state = STATE_FREE;
        chunk->ops[STATE_FREE] = oid;
    }

    check_oid(oid, 0); // see if it's time to pause
}


void post_free(uint64_t retval) {
    if (caused_by_heapalloc) return;
}


void pre_realloc(uint64_t iptr, uint64_t isize) {
    ptr = iptr;
    size = (uint64_t)isize;

    if (caused_by_heapalloc) return;

    REALLOC_COUNT++;
    uint64_t oid = get_oid();

    orig_chunk = find_chunk(ptr);

    log("%s... %s#%lu%s: realloc(", COLOR_LOG, BOLD_SYMBOL(oid));
    if (orig_chunk && orig_chunk->ops[STATE_MALLOC]) {
        // #oid symbol resolved
        log("%s#%lu%s, %s0x%02lx%s)%s\t", BOLD_SYMBOL(orig_chunk->ops[STATE_MALLOC]), BOLD(size), COLOR_RESET);
    } else {
        // could not find #oid, so just use addr
        log("%s0x%llx%s, %s0x%02lx%s)%s\t", BOLD((long long unsigned int)ptr), BOLD(size), COLOR_RESET);
    }

    if (orig_chunk && orig_chunk->state == STATE_FREE) {
        log("%s\n", COLOR_RESET);
        warn("attempting to realloc a previously-freed chunk");
        log("%s    |   * malloc()'d in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(orig_chunk->ops[STATE_MALLOC]), COLOR_RESET);
        log("%s    |   * free()'d in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(orig_chunk->ops[STATE_FREE]), COLOR_RESET);
    } else if (ptr && !orig_chunk) {
        // ptr && because https://github.com/Arinerron/heaptrace/issues/9
        //   0x0 is a special value
        log("%s\n", COLOR_RESET);
        warn("attempting to realloc a chunk that was never malloc'd");
    }

    check_oid(oid, 1); // see if it's time to pause
}


void post_realloc(uint64_t new_ptr) {
    log("%s=  %s0x%llx%s", COLOR_LOG, BOLD((long long unsigned int)new_ptr));
    if (orig_chunk && orig_chunk->ops[STATE_MALLOC]) {
        log("\t%s(%s#%lu%s%s=%s0x%llx%s)", COLOR_LOG_ITALIC, BOLD_SYMBOL(orig_chunk->ops[STATE_MALLOC]), COLOR_LOG_ITALIC, BOLD((long long unsigned int)ptr));
    }
    log("%s\n", COLOR_RESET);
    //warn("this code is untested; please report any issues you come across @ https://github.com/Arinerron/heaptrace/issues/new/choose");

    Chunk *new_chunk = find_chunk(new_ptr);

    if (ptr == new_ptr) {
        // the chunk shrank
        ASSERT(orig_chunk == new_chunk, "the new/old chunk are not equiv");
        if (orig_chunk) {
            orig_chunk->size = size;
        } // the else condition is unnecessary because there's a check above for !orig_chunk
    } else {
        if (new_ptr) {
            // the chunk moved
            new_chunk = alloc_chunk(new_ptr);
            if (new_chunk->state == STATE_MALLOC) {
                warn("realloc returned a pointer to a chunk that was never freed (but not the original chunk), which indicates some form of heap corruption");
                log("%s    |   * first malloc()'d in operation %s#%lu%s%s\n", COLOR_ERROR, BOLD_ERROR(new_chunk->ops[STATE_MALLOC]), COLOR_RESET);
            }

            new_chunk->state = STATE_MALLOC;
            new_chunk->ptr = new_ptr;
            new_chunk->size = size;
            new_chunk->ops[STATE_MALLOC] = (ptr ? orig_chunk->ops[STATE_MALLOC] : oid); // realloc can act as malloc() when ptr is 0
            new_chunk->ops[STATE_FREE] = 0;
            new_chunk->ops[STATE_REALLOC] = oid;
        } else {
            ASSERT(!size, "realloc returned NULL even though size was not zero");
        }

        if (ptr && orig_chunk) {
            orig_chunk->state = STATE_FREE;
            orig_chunk->ops[STATE_FREE] = oid;
        } // no need for else if (!orig_chunk) because !orig_chunk is above
    }

}
