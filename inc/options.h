#ifndef Breakpoint
#include "breakpoint.h"
#endif
#ifndef ProcMapsEntry
#include "proc.h"
#endif
#ifndef HeaptraceContext
#include "context.h"
#endif

extern char *symbol_defs_str;


int parse_args(int argc, char *argv[]);
void evaluate_symbol_defs(HeaptraceContext *ctx, Breakpoint **bps);
//void evaluate_symbol_defs(SymbolEntry **ses, int sesc);
