#ifndef Breakpoint
#include "breakpoint.h"
#endif
#ifndef ProcMapsEntry
#include "proc.h"
#endif

extern char *symbol_defs_str;


int parse_args(int argc, char *argv[]);
void evaluate_symbol_defs(Breakpoint **bps, int bpsc, ProcMapsEntry *pme_head);
//void evaluate_symbol_defs(SymbolEntry **ses, int sesc);
