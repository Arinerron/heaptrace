#include <stdlib.h>

#include "context.h"
#include "logging.h"

HeaptraceContext *alloc_ctx() {
    HeaptraceContext *ctx = (HeaptraceContext *)calloc(1, sizeof(HeaptraceContext));
    ctx->ret_ptr_section_type = PROCELF_TYPE_UNKNOWN;
    return ctx;
}

void *free_ctx(HeaptraceContext *ctx) {
    debug("Freeing context %p...\n", ctx);
    
    free_pme_list(ctx->pme_head);
    free(ctx->libc_version);
    free(ctx->target_interp_name);
    free_se_list(ctx->target_se_head);
    free_se_list(ctx->libc_se_head);
    free(ctx->pre_analysis_bps);
    free(ctx->se_names);

    free(ctx);
}
