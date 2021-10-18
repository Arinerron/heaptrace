#ifndef PME_H
#define PME_H

#include "util.h"

typedef enum ProcELFType {
    PROCELF_TYPE_BINARY,
    PROCELF_TYPE_LIBC,
    PROCELF_TYPE_HEAP,
    PROCELF_TYPE_STACK,
    PROCELF_TYPE_UNKNOWN
} ProcELFType;

typedef struct ProcMapsEntry {
    ProcELFType pet;
    char *name;
    uint64_t base;
    uint64_t end;

    struct ProcMapsEntry *_next;
} ProcMapsEntry;

char *get_path_by_pid(int pid);
ProcMapsEntry *build_pme_list(int pid);
ProcMapsEntry *pme_walk(ProcMapsEntry *pme_head, ProcELFType pet);
ProcMapsEntry *pme_find_addr(ProcMapsEntry *pme_head, uint64_t addr);
void free_pme_list(ProcMapsEntry *first_pme);

uint64_t get_auxv_entry(int pid);

#endif
