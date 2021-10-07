#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syscall.h>
#include <elf.h>
#include <errno.h>

#define SE_TYPE_UNRESOLVED 0
#define SE_TYPE_STATIC 1
#define SE_TYPE_DYNAMIC 2
#define SE_TYPE_DYNAMIC_PLT 3

typedef struct SymbolEntry {
    char *name;
    uint64_t offset;
    int section;
    int type; // SE_TYPE_STATIC, SE_TYPE_DYNAMIC, SE_TYPE_DYNAMIC_PLT
} SymbolEntry;

int lookup_symbols(char *fname, SymbolEntry **ses, int sesc, char **interp_name);
char *get_libc_path(char *interp_path, char *elf_path);
