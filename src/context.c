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
    ctx->ret_ptr_section_type = PROCELF_TYPE_UNKNOWN;
    ctx->target = alloc_file(ctx);
    ctx->libc = alloc_file(ctx);
    return ctx;
}

void *free_ctx(HeaptraceContext *ctx) {
    debug("Freeing context %p...\n", ctx);
    
    free_pme_list(ctx->pme_head);
    free(ctx->libc_version);
    free(ctx->pre_analysis_bps);
    free(ctx->se_names);

    free_se_list(ctx->target->se_head);
    free_se_list(ctx->libc->se_head);
    free(ctx->target);
    free(ctx->libc);

    free(ctx);
}
