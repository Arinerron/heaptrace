#include "handlers.h"
#include "logging.h"
#include "heap.h"
#include "options.h"

static size_t size;
static uint64_t ptr;
static uint64_t oid;
static Chunk *orig_chunk;


void pre_calloc(uint64_t nmemb, uint64_t isize) {
    size = (size_t)isize * (size_t)nmemb;
    
    CALLOC_COUNT++;
    oid = get_oid();

    log_heap("... " SYM ": calloc(" SZ ", " SZ ")\t", oid, (size_t)nmemb, (size_t)isize);
    check_should_break(oid, BREAK_AT, 1);
}


void post_calloc(uint64_t ptr) {
    log_heap("=  " PTR "\n", PTR_ARG(ptr));

    // store meta info
    Chunk *chunk = alloc_chunk(ptr);

    if (chunk->state == STATE_MALLOC) {
        warn_heap("calloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption");
        warn_heap2("first calloc'd in operation " SYM, chunk->ops[STATE_MALLOC]);
    }

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = size;
    chunk->ops[STATE_MALLOC] = oid;
    chunk->ops[STATE_FREE] = 0;
    chunk->ops[STATE_REALLOC] = 0;

    check_should_break(oid, BREAK_AFTER, 1);
}


void pre_malloc(uint64_t isize) {
    size = (size_t)isize;
    
    MALLOC_COUNT++;
    oid = get_oid();

    log_heap("... " SYM ": malloc(" SZ ")\t\t", oid, size);
    check_should_break(oid, BREAK_AT, 1);
}


void post_malloc(uint64_t ptr) {
    log_heap("=  " PTR "\n", PTR_ARG(ptr));

    // store meta info
    Chunk *chunk = alloc_chunk(ptr);

    if (chunk->state == STATE_MALLOC) {
        warn_heap("malloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption");
        warn_heap2("first malloc'd in operation " SYM, chunk->ops[STATE_MALLOC]);
    }

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = size;
    chunk->ops[STATE_MALLOC] = oid;
    chunk->ops[STATE_FREE] = 0;
    chunk->ops[STATE_REALLOC] = 0;

    check_should_break(oid, BREAK_AFTER, 1);
}


void pre_free(uint64_t iptr) {
    ptr = iptr;

    FREE_COUNT++;
    uint64_t oid = get_oid();

    Chunk *chunk = find_chunk(ptr);

    log_heap("... " SYM ": free(", oid);
    if (chunk && chunk->ops[STATE_MALLOC]) {
        log_heap(SYM ")\t\t   %s(" SYM_IT "=%s" PTR_IT "%s)", chunk->ops[STATE_MALLOC], COLOR_LOG_ITALIC, chunk->ops[STATE_MALLOC], COLOR_LOG_BOLD, PTR_ARG(ptr), COLOR_LOG_ITALIC);
    } else {
        log_heap(PTR ")", PTR_ARG(ptr));
    }
    //describe_symbol();
    log("\n");

    // find meta info, check to make sure it's all good
    if (!chunk) {
        if (ptr) {
            // NOTE: the if(ptr) is because NULL is explicitly allowed in man page as NOOP
            warn_heap("freeing a pointer to unknown chunk");
        }
    } else if (chunk->ptr != ptr) {
        warn_heap("freeing a pointer that is inside of a chunk");
        warn_heap2("container chunk malloc()'d in " SYM " @ " PTR " with size " SZ, chunk->ops[STATE_MALLOC], PTR_ARG(chunk->ptr), SZ_ARG(chunk->size));
    } else if (chunk->state == STATE_FREE) {
        warn_heap("attempting to double free a chunk");
        warn_heap2("first freed in operation " SYM, chunk->ops[STATE_FREE]);
        warn_heap2("malloc'd in operation " SYM, chunk->ops[STATE_MALLOC]);
    } else {
        // all is good!
        ASSERT(chunk->state != STATE_UNUSED, "cannot free unused chunk");
        chunk->state = STATE_FREE;
        chunk->ops[STATE_FREE] = oid;
    }

    check_should_break(oid, BREAK_AT, 0);
}


void post_free(uint64_t retval) {
    check_should_break(oid, BREAK_AFTER, 1);
}


// _type=1 means "realloc", _type=2 means "reallocarray"
void _pre_realloc(int _type, uint64_t iptr, uint64_t nmemb, uint64_t isize) {
    char *_name = "realloc";
    if (_type == 2) _name = "reallocarray";

    ptr = iptr;
    size = isize * nmemb;

    if (_type == 1) REALLOC_COUNT++; else if (_type == 2) REALLOCARRAY_COUNT++;
    uint64_t oid = get_oid();

    orig_chunk = find_chunk(ptr);

    log_heap("... " SYM ": %s(", oid, _name);
    if (orig_chunk && orig_chunk->ops[STATE_MALLOC]) {
        // #oid symbol resolved
        log_heap(SYM ", ", orig_chunk->ops[STATE_MALLOC]);
        if (_type == 2) log_heap(SZ ", ", SZ_ARG(nmemb));
        log_heap(SZ ")\t", SZ_ARG(isize));
    } else {
        // could not find #oid, so just use addr
        log_heap(PTR ", ", PTR_ARG(ptr));
        if (_type == 2) log_heap(SZ ", ", SZ_ARG(nmemb));
        log_heap(SZ ")\t", SZ_ARG(isize));
    }

    if (orig_chunk && orig_chunk->state == STATE_FREE) {
        log_heap("\n");
        warn_heap("attempting to %s a previously-freed chunk", _name);
        warn_heap2("allocated in operation " SYM, orig_chunk->ops[STATE_MALLOC]);
        warn_heap2("freed in operation " SYM, orig_chunk->ops[STATE_FREE]);
    } else if (ptr && !orig_chunk) {
        // ptr && because https://github.com/Arinerron/heaptrace/issues/9
        //   0x0 is a special value
        log_heap("\n");
        warn_heap("attempting to %s a chunk that was never allocated", _name);
    }

    check_should_break(oid, BREAK_AT, 1);
}


void pre_realloc(uint64_t iptr, uint64_t isize) {
    _pre_realloc(1, iptr, 1, isize);
}


void pre_reallocarray(uint64_t iptr, uint64_t nmemb, uint64_t isize) {
    _pre_realloc(2, iptr, nmemb, isize);
}


// _type=1 means "realloc", _type=2 means "reallocarray"
static void _post_realloc(int _type, uint64_t new_ptr) {
    char *_name = "realloc";
    if (_type == 2) _name = "reallocarray";

    log_heap("=  " PTR, PTR_ARG(new_ptr));
    if (orig_chunk && orig_chunk->ops[STATE_MALLOC]) {
        log("\t%s(" SYM_IT "=" PTR_IT ")", COLOR_LOG_ITALIC, orig_chunk->ops[STATE_MALLOC], PTR_ARG(ptr));
    }
    log_heap("\n");
    //warn("this code is untested; please report any issues you come across @ https://github.com/Arinerron/heaptrace/issues/new/choose");

    Chunk *new_chunk = alloc_chunk(new_ptr);

    if (ptr == new_ptr) {
        // the chunk shrank
        
        if (orig_chunk != new_chunk) {
            debug("the new/old Chunk meta are not equiv (new=" PTR_ERR ", old=" PTR_ERR ")", PTR_ARG(new_chunk), PTR_ARG(orig_chunk));
        }

        if (new_chunk) {
            new_chunk->ops[STATE_MALLOC] = oid; // NOTE: we treat it as a malloc for now
            if (orig_chunk) {
                orig_chunk->size = size;
            } // the else condition is unnecessary because there's a check above for !orig_chunk
        }
    } else {
        if (new_ptr) {
            // the chunk moved
            new_chunk = alloc_chunk(new_ptr);
            if (new_chunk->state == STATE_MALLOC) {
                warn_heap("%s returned a pointer to a chunk that was never freed (but not the original chunk), which indicates some form of heap corruption", _name);
                warn_heap2("first allocated in operation " SYM, new_chunk->ops[STATE_MALLOC]);
            }

            new_chunk->state = STATE_MALLOC;
            new_chunk->ptr = new_ptr;
            new_chunk->size = size;
            new_chunk->ops[STATE_MALLOC] = oid; // NOTE: I changed my mind. Treat it as a malloc.
            //new_chunk->ops[STATE_MALLOC] = (ptr ? orig_chunk->ops[STATE_MALLOC] : oid); // realloc can act as malloc() when ptr is 0
            new_chunk->ops[STATE_FREE] = 0;
            new_chunk->ops[STATE_REALLOC] = oid;
        } else {
            ASSERT(!size, "realloc/reallocarray returned NULL even though size was not zero");
        }

        if (ptr && orig_chunk) {
            orig_chunk->state = STATE_FREE;
            orig_chunk->ops[STATE_FREE] = oid;
        } // no need for else if (!orig_chunk) because !orig_chunk is above
    }

    check_should_break(oid, BREAK_AFTER, 1);
}

void post_realloc(uint64_t new_ptr) {
    _post_realloc(1, new_ptr);
}


void post_reallocarray(uint64_t new_ptr) {
    _post_realloc(2, new_ptr);
}
