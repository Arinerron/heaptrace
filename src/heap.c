#include "options.h"
#include "heap.h"
#include "logging.h"
#include "debugger.h"
#include "handlers.h"

// returns the current operation ID
uint64_t get_oid(HeaptraceContext *ctx) {
    uint64_t oid = ctx->malloc_count + ctx->calloc_count + ctx->free_count + ctx->realloc_count + ctx->reallocarray_count;
    ASSERT(oid < (uint64_t)0xFFFFFFFFFFFFFFF0LLU, "ran out of oids"); // avoid overflows
    return oid;
}


void show_stats(HeaptraceContext *ctx) {
    uint64_t unfreed_sum = count_unfreed_bytes(ctx->chunk_root);

    if (get_oid(ctx) || unfreed_sum) {
        if (unfreed_sum && OPT_VERBOSE) log(COLOR_LOG "------\n");
        log(COLOR_LOG "Statistics:\n");
        if (ctx->malloc_count) log("... mallocs count: " CNT "\n", ctx->malloc_count);
        if (ctx->calloc_count) log("... callocs count: " CNT "\n", ctx->calloc_count);
        if (ctx->free_count) log("... frees count: " CNT "\n", ctx->free_count);
        if (ctx->realloc_count) log("... reallocs count: " CNT "\n", ctx->realloc_count);
        if (ctx->reallocarray_count) log("... reallocarrays count: " CNT "\n" COLOR_RESET, ctx->reallocarray_count);

        if (unfreed_sum) {
            log(COLOR_ERROR "... unfreed bytes: " SZ_ERR "\n", SZ_ARG(unfreed_sum));
        }
    }

    log(COLOR_RESET);
}
