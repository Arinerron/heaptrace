#include "breakpoint.h"
#include "logging.h"

Breakpoint *breakpoints[BREAKPOINTS_COUNT] = {0};

void _add_breakpoint(int pid, Breakpoint *bp) {
    uint64_t vaddr = bp->addr;
    if (!vaddr) return;

    if (bp->pre_handler_nargs >= 4) {
        warn("warning: only up to 3 args are supported in breakpoints\n");
    }

    uint64_t orig_data = (uint64_t)ptrace(PTRACE_PEEKDATA, pid, vaddr, 0L);
    //log_heap("Installing \"%s\" breakpoint in child at %p. Original data: 0x%x\n", bp->name, vaddr, orig_data);

    bp->_is_inside = 0;
    bp->_bp = 0;
    bp->orig_data = orig_data;
    
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (!breakpoints[i]) {
            breakpoints[i] = bp;
            errno = 0;
            //printf("%x -> %x -> %x\n", orig_data, (orig_data & ~((uint64_t)0xff)), (orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
            ptrace(PTRACE_POKEDATA, pid, vaddr, (orig_data & ~((uint64_t)0xff)) | ((uint64_t)'\xcc' & (uint64_t)0xff));
            if (errno) {
                warn("heaptrace failed to install \"%s\" breakpoint at %p in process %d: %s (%d)\n", bp->name, vaddr, pid, strerror(errno), errno);
                //printf("  ... poke errno: %x (%s)\n", errno, strerror(errno));
            }
            //printf("  ... ptrace peeked 0x%x now\n", ptrace(PTRACE_PEEKDATA, pid, vaddr, 0L));
            return;
        }
    }

    warn("warning: no more breakpoints available\n");
}


void _remove_breakpoint(int pid, Breakpoint *bp) {
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (breakpoints[i] == bp) {
            breakpoints[i] = 0;
        }
    }
    
    ptrace(PTRACE_POKEDATA, pid, bp->addr, bp->orig_data);
    free(bp);
}


void _remove_breakpoints(int pid) {
    for (int i = 0; i < BREAKPOINTS_COUNT; i++) {
        if (breakpoints[i]) {
            _remove_breakpoint(pid, breakpoints[i]);
        }
    }
}
