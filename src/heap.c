#include "options.h"
#include "heap.h"

uint64_t MALLOC_COUNT = 0;
uint64_t FREE_COUNT = 0;
uint64_t REALLOC_COUNT = 0;

uint64_t break_ats[MAX_BREAK_ATS];

// initialize the chunk meta if first time
void chunk_init() {
    if (!chunks_initialized) {
        memset(chunk_meta, 0, MAX_CHUNKS * sizeof(Chunk));
        chunks_initialized = 1;
    }
}


// return the first available struct Chunk
Chunk *alloc_chunk(uint64_t ptr) {
    chunk_init();

    Chunk *first_unused = 0;

    // find first available chunk
    for (int i = 0; i < MAX_CHUNKS; i++) {
        if (!first_unused && chunk_meta[i].state == STATE_UNUSED) {
            // first store the first unused chunk found
            first_unused = &(chunk_meta[i]);
        } else if (chunk_meta[i].ptr == ptr) {
            // return the requested chunk
            return &(chunk_meta[i]);
        }
    }

    if (first_unused) {
        memset(first_unused, 0, sizeof(Chunk));
        return first_unused;
    }

    // no free chunk structs found!
    error("out of meta chunks");
    abort();
}


// return a struct Chunk containing the given addr, if any
Chunk *find_chunk(uint64_t ptr) {
    chunk_init();

    // XXX: technically it is possible to have a chunk at 0x0
    // but we don't want (ptr == cur_chunk.ptr) with uninitialized chunk metas
    if (!ptr) {
        return 0;
    }

    Chunk *next_best_chunk = 0;
    
    // find first available chunk
    Chunk cur_chunk;
    for (int i = 0; i < MAX_CHUNKS; i++) {
        cur_chunk = chunk_meta[i];
        // XXX: remember, malloc.c rounds size up!
        if (ptr == cur_chunk.ptr) {
            return &(chunk_meta[i]);
        } else if (!next_best_chunk && ptr >= cur_chunk.ptr && ptr <= cur_chunk.ptr + CHUNK_SIZE(cur_chunk.size)) {
            // this is to simplify chunk consolidation logic. it's not perfect but it works in most cases
            next_best_chunk = &(chunk_meta[i]);
        }
    }

    return next_best_chunk;
}


// see if it's time to pause
void check_oid(uint64_t oid, int prepend_newline) {
    // TODO
    if (!args_parsed_yet) {
        //parse_arguments(); // TODO
        args_parsed_yet = 1;
    }

    int should_break = OPT_BREAK;
    // try reading from params second
    if (!should_break) {
        for (int i = 0; i < MAX_BREAK_ATS; i++) {
            if (break_ats[i] == oid) {
                should_break = 1;
            }
        }
    }

    // now actually break if necessary
    if (should_break) {
        if (prepend_newline) log("\n"); // XXX: this hack is because malloc/realloc need a newline before paused msg
        log("%s    [   PROCESS PAUSED   ]%s\n", COLOR_ERROR, COLOR_RESET);
        log("%s    |   * to attach GDB: %sgdb -p %d%s%s\n", COLOR_ERROR, BOLD_ERROR(getpid()), COLOR_RESET);
        log("%s    |   * to resume process: %s%s%s OR %skill -CONT %d%s%s\n", COLOR_ERROR, BOLD_ERROR("fg"), BOLD_ERROR(getpid()), COLOR_RESET);
        if (prepend_newline) log("    "); // XXX/HACK: see above
        raise(SIGSTOP);
    }
}


// returns the current operation ID
uint64_t get_oid() {
    uint64_t oid = MALLOC_COUNT + FREE_COUNT + REALLOC_COUNT;
    ASSERT(oid < (uint64_t)0xFFFFFFFFFFFFFFF0LLU, "ran out of oids"); // avoid overflows
    return oid;
}


void show_stats() {
    log("%s\n================================= %s%s%s ================================\n", COLOR_LOG, BOLD("END HEAPTRACE"));

    uint64_t unfreed_sum = 0;
    Chunk cur_chunk;
    for (int i = 0; i < MAX_CHUNKS; i++) {
        cur_chunk = chunk_meta[i];
        if (cur_chunk.state == STATE_MALLOC) {
            if (OPT_VERBOSE) {
                log("%s* chunk malloc'd in operation %s#%lu%s was never freed\n", COLOR_ERROR, BOLD_ERROR(cur_chunk.ops[STATE_MALLOC]));
            }
            unfreed_sum += CHUNK_SIZE(cur_chunk.size);
        }
    }

    if (unfreed_sum && OPT_VERBOSE) log("%s------\n", COLOR_LOG);
    log("Statistics:\n");
    log("... total mallocs: %s%lu%s\n", BOLD(MALLOC_COUNT));
    log("... total frees: %s%lu%s\n", BOLD(FREE_COUNT));
    log("... total reallocs: %s%lu%s\n", BOLD(REALLOC_COUNT));

    if (unfreed_sum) {
        log("%s... total bytes lost: %s0x%lx%s\n", COLOR_ERROR, BOLD_ERROR(unfreed_sum));
    }

    log("%s", COLOR_RESET);
}
