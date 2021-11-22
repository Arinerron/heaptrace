#include "breakpoint.h"
#include "logging.h"


void install_breakpoint(HeaptraceContext *ctx, Breakpoint *bp) {
    uint64_t vaddr = bp->addr;
    if (!vaddr) return;

    if (bp->pre_handler_nargs >= 4) {
        warn("only up to 3 args are supported in breakpoints\n");
    }

    uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKDATA, ctx->pid, vaddr, NULL);
    debug("installing \"%s\" breakpoint in child at " U64T ". Original data: " U64T "\n", bp->name, vaddr, orig_data);

    bp->_is_inside = 0;
    bp->_bp = 0;
    bp->orig_data = orig_data;
    
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (ctx->breakpoints[i]) {
            //ASSERT(ctx->breakpoints[i]->addr != bp->addr, "cannot add two breakpoints with the same address (breakpoints[i] = %s @ " U64T ", bp = %s @ " U64T ")", ctx->breakpoints[i]->name, ctx->breakpoints[i]->addr, bp->name, bp->addr)
            if (ctx->breakpoints[i]->addr == bp->addr) {
                bp->orig_data = ctx->breakpoints[i]->orig_data;
            }
        } else {
            ctx->breakpoints[i] = bp;
            errno = 0;
            PTRACE(PTRACE_POKEDATA, ctx->pid, vaddr, (orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
            if (errno) {
                warn("heaptrace failed to install \"%s\" breakpoint at " U64T " in process %u: %s (%d)\n", bp->name, vaddr, ctx->pid, strerror(errno), errno);
            }
            return;
        }
    }

    ASSERT(0, "no more breakpoints available. Please report this.\n");
}


// TODO: convert into linked list
void _remove_breakpoint(HeaptraceContext *ctx, Breakpoint *bp, int opts) {
    if (opts & BREAKPOINT_OPT_UNREGISTER || opts & BREAKPOINT_OPT_FREE) {
        for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
            if (ctx->breakpoints[i] == bp) {
                ctx->breakpoints[i] = 0;
            }
        }
    }
    
    if (opts & BREAKPOINT_OPT_REMOVE) {
        ptrace(PTRACE_POKEDATA, ctx->pid, bp->addr, bp->orig_data); // ignore error
    }

    if (opts & BREAKPOINT_OPT_FREE) {
        free(bp);
    }
}


// TODO: convert into linked list
void _remove_breakpoints(HeaptraceContext *ctx, int opts) {
    debug("removing all breakpoints...\n");
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (ctx->breakpoints[i]) {
            _remove_breakpoint(ctx, ctx->breakpoints[i], opts);
        }
    }
}
