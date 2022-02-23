#include <stdlib.h>

#include "context.h"
#include "logging.h"


HeaptraceFile *alloc_file(HeaptraceContext *ctx) {
    HeaptraceFile *f = (HeaptraceFile *)calloc(1, sizeof(HeaptraceFile));
    f->ctx = ctx;
    return f;
}


HeaptraceContext *alloc_ctx() {
    HeaptraceContext *ctx = (HeaptraceContext *)calloc(1, sizeof(HeaptraceContext));
    ctx->h_ret_ptr_section_type = PROCELF_TYPE_UNKNOWN;
    ctx->target = alloc_file(ctx);
    ctx->libc = alloc_file(ctx);
    ctx->hlm.warnings = malloc(HLM_WARNINGS_SIZE + 2);
    return ctx;
}


void *free_ctx(HeaptraceContext *ctx) {
    debug("Freeing context %p...\n", ctx);
    
    printf("\nasdf\n");
    free_pme_list(ctx->pme_head);
    free(ctx->libc_version);
    free(ctx->pre_analysis_bps);
    free(ctx->se_names);

    free_se_list(ctx->target->se_head);
    free_se_list(ctx->target->all_static_se_head);
    free_se_list(ctx->libc->se_head);
    free_se_list(ctx->libc->all_static_se_head);
    free(ctx->target);
    free(ctx->libc);

    free_chunks(ctx);

    free(ctx->hlm.warnings);
    free_hlm_notes_head(ctx);

    free(ctx);
}


void show_stats(HeaptraceContext *ctx) {
    uint64_t unfreed_sum = count_unfreed_bytes(ctx->chunk_root);

    if (GET_OID() || unfreed_sum) {
        color_log(COLOR_LOG);
        log("Statistics:\n");
        if (ctx->malloc_count) log("... mallocs count: " CNT "\n", ctx->malloc_count);
        if (ctx->calloc_count) log("... callocs count: " CNT "\n", ctx->calloc_count);
        if (ctx->free_count) log("... frees count: " CNT "\n", ctx->free_count);
        if (ctx->realloc_count) log("... reallocs count: " CNT "\n", ctx->realloc_count);
        if (ctx->reallocarray_count) log("... reallocarrays count: " CNT "\n", ctx->reallocarray_count);
        color_log(COLOR_RESET);

        if (unfreed_sum) {
            color_log(COLOR_ERROR);
            log("... unfreed bytes: " SZ_ERR "\n", SZ_ARG(unfreed_sum));
        }
    }

    log(COLOR_RESET);
}
