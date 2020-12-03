#define _GNU_SOURCE
#include <malloc.h>
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>

#define STATE_UNUSED 0
#define STATE_MALLOC 1
#define STATE_FREE 2
#define STATE_REALLOC 3

#define COLOR_LOG "\e[0;36m"
#define COLOR_LOG_BOLD "\e[1;36m"
#define COLOR_ERROR "\e[0;31m"
#define COLOR_ERROR_BOLD "\e[1;31m"
#define COLOR_RESET "\e[0m"

static FILE *output_fd;

#define log(f_, ...) { fprintf(output_fd, (f_), ##__VA_ARGS__); } // XXX: ansi colors to file?
#define BOLD(msg) COLOR_LOG_BOLD, (msg), COLOR_LOG // %s%d%s
#define BOLD_ERROR(msg) COLOR_ERROR_BOLD, (msg), COLOR_ERROR // %s%d%s
#define error(msg) log("%sheaptrace error: %s%s%s\n", COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET) 
#define warn(msg) log("%s    |-- %swarning: %s%s%s\n", COLOR_ERROR, COLOR_ERROR_BOLD, COLOR_ERROR, (msg), COLOR_RESET)

#define ASSERT(q, msg) if (!(q)) { error(msg); abort(); }

void *(*orig_malloc)(size_t size);
void (*orig_free)(void *ptr);
void *(*orig_realloc)(void *ptr, size_t size);
void (*orig_exit)(int status) __attribute__ ((noreturn));
static int (*main_orig)(int, char **, char **);


//////////


static uint64_t MALLOC_COUNT = 0, FREE_COUNT = 0, REALLOC_COUNT;


////////// CHUNK META CHUNK


typedef struct Chunk {
    int state;
    void *ptr;
    uint64_t size;

    uint64_t ops[4]; // for tracking where ops happened: [malloc_oid, free_oid]
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

    // XXX: technically it is possible to have a chunk at 0x0
    // but we don't want (ptr == cur_chunk.ptr) with uninitialized chunk metas
    if (!ptr) {
        return 0;
    }
    
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

static int args_parsed_yet = 0;
static int OPT_BREAK = 0; // break on every operation?
static int OPT_VERBOSE = 0; // show a stack trace on every operation?

#define MAX_ARGS 1024
char *argv[MAX_ARGS];

#define MAX_BREAK_ATS 0xff
uint64_t break_ats[MAX_BREAK_ATS];

void parse_arguments() {
    memset(break_ats, 0, sizeof(uint64_t) * MAX_BREAK_ATS);

    char *args = getenv("HEAPTRACE_ARGS");
    if (args) {
        int argv_i = 0, args_i = 0;

        // parse char *args into char **argv
        argv[argv_i++] = args;
        while (args[args_i] != 0) {
            ASSERT(argv_i < MAX_ARGS, "maximum number of arguments reached");
            // XXX/HACK: very hacky arg parsing
            if (args[args_i] == ' ' || args[args_i] == '=') {
                args[args_i] = 0;
                // if the next byte is not also ' '
                if (args[args_i + 1] != ' ') {
                    argv[argv_i++] = args + args_i + 1;
                }
            }
            
            args_i++;
        }

        int argc = argv_i;

        // parse char **argv
        #define EXPECT_ARG ASSERT(i + 1 < argc, "an argument requires a parameter"); i++;
        for (int i = 0; i < argc; i++) {
            char *arg = argv[i];

            if (!strcmp(arg, "--break")) {
                OPT_BREAK = 1;
            } else if (!strcmp(arg, "--verbose") || !strcmp(arg, "-v")) {
                OPT_VERBOSE = 1;
            } else if (!strcmp(arg, "--break-at") || !strcmp(arg, "-b")) {
                EXPECT_ARG;
                char *arg2 = argv[i];
                for (int i2 = 0; i2 < MAX_BREAK_ATS; i2++) {
                    if (break_ats[i2] == 0) {
                        char *endp;
                        break_ats[i2] = strtoul(arg2, &endp, 10);
                        break;
                    }
                }
            } else if (!strcmp(arg, "--output") || !strcmp(arg, "-o")) {
                EXPECT_ARG;
                output_fd = fopen(argv[i], "w"); // can't use fopen because it malloc()s
                if (!output_fd) {
                    output_fd = stderr;
                    log("failed to open file: %s\n", argv[i]);
                    _exit(1);
                }
            } else {
                log("unknown argument: %s\n", arg);
                _exit(1);
            }
        }

        unsetenv("HEAPTRACE_ARGS");
    }

    args_parsed_yet = 1;
}


// see if it's time to pause
void check_oid(uint64_t oid, int prepend_newline) {
    // TODO
    if (!args_parsed_yet) {
        parse_arguments();
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


////////// HELPERS


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
            log("%s* chunk malloc'd in operation #%s%lu%s was never freed\n", COLOR_ERROR, BOLD_ERROR(cur_chunk.ops[STATE_MALLOC]));
            unfreed_sum += cur_chunk.size;
        }
    }

    if (unfreed_sum) log("%s------\n", COLOR_LOG);
    log("Statistics:\n");
    log("... total mallocs: %s%lu%s\n", BOLD(MALLOC_COUNT));
    log("... total frees: %s%lu%s\n", BOLD(FREE_COUNT));
    log("... total reallocs: %s%lu%s\n", BOLD(REALLOC_COUNT));

    if (unfreed_sum) {
        log("%s... total bytes lost: %s0x%lx%s\n", COLOR_ERROR, BOLD_ERROR(unfreed_sum));
    }

    log("%s", COLOR_RESET);
}


//////////


static int caused_by_heapalloc = 1;


void *malloc(size_t size) {
    if (caused_by_heapalloc) return orig_malloc(size);

    MALLOC_COUNT++;
    uint64_t oid = get_oid();

    if (size == 0) {
        warn("attempting a zero malloc");
    }

    log("%s... #%s%lu%s: malloc(%s0x%02lx%s)\t%s", COLOR_LOG, BOLD(oid), BOLD(size), COLOR_RESET);
    check_oid(oid, 1); // see if it's time to pause
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
    chunk->ops[STATE_REALLOC] = 0;

    return ptr;
}


void free(void *ptr) {
    if (caused_by_heapalloc) {
        orig_free(ptr);
        return;
    }

    FREE_COUNT++;
    uint64_t oid = get_oid();

    log("%s... #%s%lu%s: free(%s0x%llx%s)%s\n", COLOR_LOG, BOLD(oid), BOLD((long long unsigned int)ptr), COLOR_RESET);

    // find meta info, check to make sure it's all good
    Chunk *chunk = find_chunk(ptr);
    if (!chunk) {
        warn("freeing a pointer to something that is not a chunk");
    } else if (chunk->ptr != ptr) {
        warn("freeing a pointer that is inside of a chunk");
    } else if (chunk->state == STATE_FREE) {
        warn("attempting to double free a chunk");
        log("%s    |   * malloc'd in operation #%lu%s\n", COLOR_ERROR, chunk->ops[STATE_MALLOC], COLOR_RESET);
        log("%s    |   * first freed in operation #%lu%s\n", COLOR_ERROR, chunk->ops[STATE_FREE], COLOR_RESET);
    } else {
        // all is good!
        ASSERT(chunk->state != STATE_UNUSED, "cannot free unused chunk");
        chunk->state = STATE_FREE;
        chunk->ops[STATE_FREE] = oid;
    }

    check_oid(oid, 0); // see if it's time to pause
    orig_free(ptr);
}

void *realloc(void *ptr, size_t size) {
    if (caused_by_heapalloc) return orig_realloc(ptr, size);
    REALLOC_COUNT++;
    uint64_t oid = get_oid();

    log("%s... #%s%lu%s: realloc(%s0x%llx%s, %s0x%02lx%s)%s\t", COLOR_LOG, BOLD(oid), BOLD((long long unsigned int)ptr), BOLD(size), COLOR_RESET);
    check_oid(oid, 1); // see if it's time to pause
    void *new_ptr = orig_realloc(ptr, size);
    log("%s = %s0x%llx%s\n", COLOR_LOG, COLOR_LOG_BOLD, (long long unsigned int)new_ptr, COLOR_RESET);
    warn("this code is untested; please report any issues you come across @ https://github.com/Arinerron/heaptrace/issues/new/choose");

    Chunk *orig_chunk = find_chunk(ptr);
    Chunk *new_chunk = find_chunk(new_ptr);
    if (ptr == new_ptr) {
        // the chunk shrank
        ASSERT(orig_chunk == new_chunk, "the new/old chunk are not equiv");
        orig_chunk->size = size;
    } else if (new_ptr) {
        // the chunk moved
        new_chunk = alloc_chunk(new_ptr);
        if (new_chunk->state == STATE_MALLOC) {
            warn("realloc returned a pointer to a chunk that was never freed (but not the original chunk), which indicates some form of heap corruption");
        }

        new_chunk->state = STATE_MALLOC;
        new_chunk->ptr = new_ptr;
        new_chunk->size = size;
        new_chunk->ops[STATE_MALLOC] = (ptr ? orig_chunk->ops[STATE_MALLOC] : oid); // realloc can act as malloc() when ptr is 0
        new_chunk->ops[STATE_FREE] = 0;
        new_chunk->ops[STATE_REALLOC] = oid;
    } else {
        // we freed the chunk
        ASSERT(!size, "realloc returned NULL even though size was not zero");

    }

    return new_ptr;
}


void exit(int status) {
    show_stats();
    orig_exit(status);
}


int main_hook(int argc, char **argv, char **envp) {
    int retval = main_orig(argc, argv, envp);
    show_stats();
    return retval;
}


// https://gist.github.com/apsun/1e144bf7639b22ff0097171fa0f8c6b1
int __libc_start_main( int (*main)(int, char **, char **), int argc, char **argv, int (*init)(int, char **, char **), void (*fini)(void), void (*rtld_fini)(void), void *stack_end) {
    main_orig = main;
    typeof(&__libc_start_main) orig = dlsym(RTLD_NEXT, "__libc_start_main");
    return orig(main_hook, argc, argv, init, fini, rtld_fini, stack_end);
}


//////////


void _init(void) {
    if (!orig_malloc) orig_malloc = dlsym(RTLD_NEXT, "malloc");
    if (!orig_free) orig_free = dlsym(RTLD_NEXT, "free");
    if (!orig_realloc) orig_realloc = dlsym(RTLD_NEXT, "realloc");
    if (!orig_exit) orig_exit = dlsym(RTLD_NEXT, "exit");
    output_fd = stderr;
    parse_arguments();
    log("%s================================ %s%s%s ===============================\n%s\n", COLOR_LOG, BOLD("BEGIN HEAPTRACE"), COLOR_RESET);
    caused_by_heapalloc = 0;
}
