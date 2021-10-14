#ifndef PME_H
#define PME_H

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

void free_pme_list(ProcMapsEntry *first_pme);
ProcMapsEntry *build_pme_list(int pid);
ProcMapsEntry *pme_walk(ProcMapsEntry *pme_head, ProcELFType pet);

uint64_t get_auxv_entry(int pid);

#endif
