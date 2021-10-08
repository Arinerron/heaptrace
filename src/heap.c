#include "options.h"
#include "heap.h"
#include "logging.h"
#include "debugger.h"

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
    fatal("out of meta chunks");
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

    // try reading from params second
    int should_break = 0;
    for (int i = 0; i < MAX_BREAK_ATS; i++) {
        if (break_ats[i] == oid) {
            should_break = 1;
        }
    }

    // now actually break if necessary
    if (should_break) {
        if (prepend_newline) log("\n"); // XXX: this hack is because malloc/realloc need a newline before paused msg
        log(COLOR_ERROR "    [   PROCESS PAUSED   ]\n");
        log(COLOR_ERROR "    |   * attaching GDB via: " COLOR_ERROR_BOLD "/usr/bin/gdb -p %d\n" COLOR_RESET, CHILD_PID);
        if (prepend_newline) log("    "); // XXX/HACK: see above

        // launch gdb
        _remove_breakpoints(CHILD_PID);
        ptrace(PTRACE_DETACH, CHILD_PID, NULL, SIGSTOP);

        char buf[10+1];
        snprintf(buf, 10, "%d", CHILD_PID);
        char *gdb_path = "/usr/bin/gdb";
        char *args[] = {gdb_path, "-p", buf, NULL};
        if (execv(args[0], args) == -1) {
            fatal("failed to execute debugger %s: %s (errno %d)", args[0], strerror(errno), errno);
            abort();
        }
        //raise(SIGSTOP);
    }
}


// returns the current operation ID
uint64_t get_oid() {
    uint64_t oid = MALLOC_COUNT + FREE_COUNT + REALLOC_COUNT;
    ASSERT(oid < (uint64_t)0xFFFFFFFFFFFFFFF0LLU, "ran out of oids"); // avoid overflows
    return oid;
}


void show_stats() {
    uint64_t unfreed_sum = 0;
    Chunk cur_chunk;
    int _prefix = 0; // hack for getting newlines right
    for (int i = 0; i < MAX_CHUNKS; i++) {
        cur_chunk = chunk_meta[i];
        if (cur_chunk.state == STATE_MALLOC) {
            if (OPT_VERBOSE) {
                if (!_prefix) {
                    _prefix = 1;
                    log("\n");
                }
                log(COLOR_ERROR "* chunk malloc'd in operation " SYM COLOR_ERROR " was never freed\n", cur_chunk.ops[STATE_MALLOC]);
            }
            unfreed_sum += CHUNK_SIZE(cur_chunk.size);
        }
    }

    if (unfreed_sum && OPT_VERBOSE) log(COLOR_LOG "------\n");
    log(COLOR_LOG "Statistics:\n");
    log("... total mallocs: " CNT "\n", MALLOC_COUNT);
    log("... total frees: " CNT "\n", FREE_COUNT);
    log("... total reallocs: " CNT "\n" COLOR_RESET, REALLOC_COUNT);

    if (unfreed_sum) {
        log(COLOR_ERROR "... total bytes lost: " SZ_ERR "\n", SZ_ARG(unfreed_sum));
    }

    log("%s", COLOR_RESET);
}
