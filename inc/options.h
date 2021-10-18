#include "util.h"
#include "breakpoint.h"
#include "proc.h"
#include "context.h"

extern char *symbol_defs_str;

int parse_args(int argc, char *argv[]);
void evaluate_symbol_defs(HeaptraceContext *ctx, Breakpoint **bps);
//void evaluate_symbol_defs(SymbolEntry **ses, int sesc);
