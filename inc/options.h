#ifndef Breakpoint
#include "breakpoint.h"
#endif

extern char *symbol_defs_str;


int parse_args(int argc, char *argv[]);
void evaluate_symbol_defs(Breakpoint **bps, int bpsc, uint64_t libc_base, uint64_t bin_base);
//void evaluate_symbol_defs(SymbolEntry **ses, int sesc);
