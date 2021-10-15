#include "breakpoint.h"
#include "logging.h"

Breakpoint *breakpoints[BREAKPOINTS_COUNT] = {0};

void install_breakpoint(HeaptraceContext *ctx, Breakpoint *bp) {
    uint64_t vaddr = bp->addr;
    if (!vaddr) return;

    if (bp->pre_handler_nargs >= 4) {
        warn("only up to 3 args are supported in breakpoints\n");
    }

    uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKDATA, ctx->pid, vaddr, NULL);
    debug("installing \"%s\" breakpoint in child at %p. Original data: 0x%x\n", bp->name, vaddr, orig_data);

    bp->_is_inside = 0;
    bp->_bp = 0;
    bp->orig_data = orig_data;
    
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (!breakpoints[i]) {
            breakpoints[i] = bp;
            errno = 0;
            ptrace(PTRACE_POKEDATA, ctx->pid, vaddr, (orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
            if (errno) {
                warn("heaptrace failed to install \"%s\" breakpoint at %p in process %d: %s (%d)\n", bp->name, vaddr, ctx->pid, strerror(errno), errno);
            }
            return;
        }
    }

    ASSERT(0, "no more breakpoints available. Please report this.\n");
}


// TODO: convert into linked list
void _remove_breakpoint(HeaptraceContext *ctx, Breakpoint *bp, int should_free) {
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (breakpoints[i] == bp) {
            breakpoints[i] = 0;
        }
    }
    
    ptrace(PTRACE_POKEDATA, ctx->pid, bp->addr, bp->orig_data);
    if (should_free) free(bp);
}


// TODO: convert into linked list
void _remove_breakpoints(HeaptraceContext *ctx, int should_free) {
    debug("removing all breakpoints...\n");
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (breakpoints[i]) {
            _remove_breakpoint(ctx, breakpoints[i], should_free);
        }
    }
}
