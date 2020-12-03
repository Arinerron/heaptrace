#define _GNU_SOURCE
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <getopt.h>
#include <assert.h>

#define STATE_UNUSED 0
#define STATE_MALLOC 1
#define STATE_FREE 2

#define COLOR_LOG "\e[0;36m"
#define COLOR_LOG_BOLD "\e[1;36m"
#define COLOR_ERROR "\e[0;31m"
#define COLOR_ERROR_BOLD "\e[1;31m"
#define COLOR_RESET "\e[0m"

#define log(f_, ...) fprintf(stderr, (f_), ##__VA_ARGS__)
#define BOLD(msg) COLOR_LOG_BOLD, (msg), COLOR_LOG // %s%d%s
#define error(msg) log("%sheaptrace error: %s%s%s\n", COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET) 
#define warn(msg) log("%s    |-- %swarning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET)

void *(*orig_malloc)(size_t size);
void (*orig_free)(void *ptr);
void (*orig_exit)(int status) __attribute__ ((noreturn));


//////////


static uint64_t MALLOC_COUNT = 0, FREE_COUNT = 0;


////////// CHUNK META CHUNK


typedef struct Chunk {
    int state;
    void *ptr;
    uint64_t size;

    uint64_t ops[3]; // for tracking where ops happened: [malloc_oid, free_oid]
} Chunk;

#define MAX_META_SIZE 8*8388600 // 64 MB
#define MAX_CHUNKS MAX_META_SIZE / sizeof(Chunk)

static int chunks_initialized = 0;
static Chunk chunk_meta[MAX_CHUNKS];


// initialize the chunk meta if first time
void chunk_init() {
    if (!chunks_initialized) {
        memset(chunk_meta, 0, MAX_CHUNKS * sizeof(Chunk));
        chunks_initialized = 1;
    }
}


// return the first available struct Chunk
Chunk *alloc_chunk(void *ptr) {
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
        return first_unused;
    }

    // no free chunk structs found!
    error("out of meta chunks");
    abort();
}


// return a struct Chunk containing the given addr, if any
Chunk *find_chunk(void *ptr) {
    chunk_init();
    
    // find first available chunk
    Chunk cur_chunk;
    for (int i = 0; i < MAX_CHUNKS; i++) {
        cur_chunk = chunk_meta[i];
        // XXX: remember, malloc.c rounds size up!
        if (ptr >= cur_chunk.ptr && ptr <= cur_chunk.ptr + cur_chunk.size) {
            return &(chunk_meta[i]);
        }
    }

    return 0;
}


////////// ARGUMENTS

static int OPT_BREAK = 0; // break on every operation?
static int OPT_VERBOSE = 0; // show a stack trace on every operation?

void parse_arguments() {
    static struct option long_options[] = {
        { "break", no_argument, &OPT_BREAK, 1 },
        { "break-at", required_argument, 0, 'b' },
        { "verbose", no_argument, &OPT_VERBOSE, 1 },
        { "verbose-at", required_argument, 0, 'v' },
        { 0, 0, 0, 0 }
    };

    printf("%p\n", long_options);

    // TODO
}

// see if it's time to pause
void check_oid(uint64_t oid) {
    // TODO
}


////////// OID 


// returns the current operation ID
uint64_t get_oid() {
    uint64_t oid = MALLOC_COUNT + FREE_COUNT;
    assert(oid < (uint64_t)0xFFFFFFFFFFFFFFF0LLU); // avoid overflows
    return oid;
}


//////////


void *malloc(size_t size) {
    MALLOC_COUNT++;
    uint64_t oid = get_oid();

    if (size == 0) {
        warn("attempting a zero malloc");
    }

    log("%s... #%s%lu%s: malloc(%s0x%02lx%s)\t%s", COLOR_LOG, BOLD(oid), BOLD(size), COLOR_RESET);
    check_oid(oid); // see if it's time to pause
    void *ptr = orig_malloc(size);
    log("%s = %s0x%llx%s\n", COLOR_LOG, COLOR_LOG_BOLD, (long long unsigned int)ptr, COLOR_RESET);

    // store meta info
    Chunk *chunk = alloc_chunk(ptr);

    if (chunk->state == STATE_MALLOC) {
        warn("malloc returned a pointer to a chunk that was never freed, which indicates some form of heap corruption");
    }

    chunk->state = STATE_MALLOC;
    chunk->ptr = ptr;
    chunk->size = size;
    chunk->ops[STATE_MALLOC] = oid;
    chunk->ops[STATE_FREE] = 0;

    return ptr;
}


void free(void *ptr) {
    FREE_COUNT++;
    uint64_t oid = get_oid();

    log("%s... #%s%lu%s: free(%s0x%llx%s)%s\n", COLOR_LOG, BOLD(oid), BOLD((long long unsigned int)ptr), COLOR_RESET);

    // find meta info, check to make sure it's all good
    Chunk *chunk = find_chunk(ptr);
    if (!chunk) {
        warn("freeing a non-chunk pointer");
    } else if (chunk->ptr != ptr) {
        warn("attempting to free a pointer that is inside of a chunk");
    } else if (chunk->state == STATE_FREE) {
        warn("attempting to double free a chunk");
        log("%s    |   * malloc()'d in operation #%lu%s\n", COLOR_ERROR, chunk->ops[STATE_MALLOC], COLOR_RESET);
        log("%s    |   * first free()'d in operation #%lu%s\n", COLOR_ERROR, chunk->ops[STATE_FREE], COLOR_RESET);
    } else {
        // all is good!
        assert(chunk->state != STATE_UNUSED);
        chunk->state = STATE_FREE;
        chunk->ops[STATE_FREE] = oid;
    }

    check_oid(oid); // see if it's time to pause
    orig_free(ptr);
}


void exit(int status) {
    log("%sFinished heaptrace. Statistics:\n", COLOR_LOG);
    log("... total mallocs: %s%lu%s\n", COLOR_LOG_BOLD, MALLOC_COUNT, COLOR_LOG);
    log("... total frees: %s%lu%s\n", COLOR_LOG_BOLD, FREE_COUNT, COLOR_RESET);
    orig_exit(status);
}


//////////


void _init(void) {
    if (!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!orig_free) orig_free = dlsym(RTLD_NEXT, "free");
    if (!orig_exit) orig_exit = dlsym(RTLD_NEXT, "exit");
    log("%sInitialized heaptrace.%s\n", COLOR_LOG, COLOR_RESET);
}
