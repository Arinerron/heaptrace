#ifndef SYMBOL_H
#define SYMBOL_H

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <elf.h>
#include <errno.h>

#include "util.h"
#include "context.h"

#define SE_TYPE_UNRESOLVED 0
#define SE_TYPE_STATIC 1
#define SE_TYPE_DYNAMIC 2
#define SE_TYPE_DYNAMIC_PLT 3

typedef struct SymbolEntry {
    char *name;
    uint64_t offset;
    uint64_t size;
    int section;
    int type; // SE_TYPE_STATIC, SE_TYPE_DYNAMIC, SE_TYPE_DYNAMIC_PLT

    int64_t _sub_offset;
    struct SymbolEntry *_next;
} SymbolEntry;

void lookup_symbols(HeaptraceFile *hf, char *names[]);
SymbolEntry *any_se_type(SymbolEntry *se_head, int type);
int all_se_type(SymbolEntry *se_head, int type);
SymbolEntry *find_se_name(SymbolEntry *se_head, char *name);
void free_se_list(SymbolEntry *se_head);

SymbolEntry *find_symbol_by_address(HeaptraceFile *hf, uint64_t addr);
HeaptraceFile *find_heaptrace_file_by_address(HeaptraceContext *ctx, uint64_t addr);
char *find_symbol_name_by_address(HeaptraceContext *ctx, uint64_t addr);

char *get_source_function(HeaptraceContext *ctx);

#endif
