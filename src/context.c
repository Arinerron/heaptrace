#include <stdlib.h>

#include "context.h"

HeaptraceContext *alloc_ctx() {
    HeaptraceContext *ctx = (HeaptraceContext *)calloc(1, sizeof(HeaptraceContext));
    ctx->ret_ptr_section_type = PROCELF_TYPE_UNKNOWN;
    return ctx;
}

void *free_ctx(HeaptraceContext *ctx) {
    _remove_breakpoints(ctx, 1);
    free_pme_list(ctx->pme_head);
    free(ctx->libc_path);
    free(ctx->libc_version);
    free(ctx->target_interp_name);
    free(ctx);
}
