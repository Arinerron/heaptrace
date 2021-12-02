#include <stdlib.h>
#include <inttypes.h>
#include <sys/personality.h>
#include <linux/auxvec.h>
#include <errno.h>

#include "proc.h"
#include "logging.h"

static const int MAX_PATH_SIZE = 4096; // WARNING: If you change this, grep for all uses of 4096! It's hardcoded in a few format strs


void free_pme_list(ProcMapsEntry *first_pme) {
    ProcMapsEntry *pme = first_pme;
    while(pme) {
        ProcMapsEntry *next_pme = pme->_next;
        free(pme->name);
        free(pme);
        pme = next_pme;
    }
}


char *get_path_by_pid(int pid) {
    // get the full path to the binary
    char *exepath = malloc(MAX_PATH_SIZE + 1);
    char *fname = malloc(MAX_PATH_SIZE + 1);
    snprintf(exepath, MAX_PATH_SIZE, "/proc/%d/exe", pid);
    
    ssize_t nbytes = readlink(exepath, fname, MAX_PATH_SIZE);
    if (nbytes == -1) {
        debug("debug warning: failed to readlink %s. Is the process dead?\n", exepath);
        free(exepath);
        free(fname);
        return 0;
    }

    fname[nbytes] = '\x00';
    free(exepath);
    return fname;
}


ProcMapsEntry *build_pme_list(int pid) {
    char *fname = get_path_by_pid(pid);

    // get the path to the /proc/pid/maps file
    char *mapspath = malloc(MAX_PATH_SIZE + 1);
    snprintf(mapspath, MAX_PATH_SIZE, "/proc/%d/maps", pid);
    FILE *f = fopen(mapspath, "r");
    if (!f) {
        warn("failed to open process maps (%s)\n", mapspath);
        free(fname);
        return 0;
    }

    
    ProcMapsEntry *pme_head = 0;
    ProcMapsEntry *pme = 0;

    char *cur_fname = malloc(MAX_PATH_SIZE + 2);
    uint64_t cur_section_base = 0;
    uint64_t cur_section_end = 0;
    uint64_t _tmp[9]; // sorry I'm a terible programmer
    while (1) {
        #define WH "%*[ \t]c" // whitespace
        if (fscanf(f, "%lx-%lx" WH, &cur_section_base, &cur_section_end) == EOF) { // 7f738fb9f000-7f738fba0000
            break;
        }

        size_t dummy;
        dummy = fscanf(f, "%*s" WH);
        dummy = fscanf(f, "%*s" WH);
        dummy = fscanf(f, "%*x:%*x" WH); // 103:08
        dummy = fscanf(f, "%*s" WH);

        memset(cur_fname, 0, MAX_PATH_SIZE + 1);
        dummy = fscanf(f, "%4096[^\n]s\n", cur_fname); // 18615725
        if (!pme || strcmp(pme->name, cur_fname)) { // if the name changed or first run
            pme = calloc(1, sizeof(ProcMapsEntry));
            pme->pet = PROCELF_TYPE_UNKNOWN;
            pme->name = strdup(cur_fname);

            // insert into list
            pme->_next = pme_head;
            pme_head = pme;
        }

        if (!strcmp(fname, cur_fname)) {
            pme->pet = PROCELF_TYPE_BINARY;
        } else if (strstr(cur_fname, "libc-") || strstr(cur_fname, "libc.so")) { // XXX: quite a hack
            pme->pet = PROCELF_TYPE_LIBC;
        } else if (!strcmp("[heap]", cur_fname)) {
            pme->pet = PROCELF_TYPE_HEAP;
        } else if (!strcmp("[stack]", cur_fname)) {
            pme->pet = PROCELF_TYPE_STACK;
        }

        if (!pme->base || (pme->base && cur_section_base < pme->base)) {
            pme->base = cur_section_base;
        }
        if (!pme->end || (pme->end && cur_section_end > pme->end)) {
            pme->end = cur_section_end;
        }

        debug("PME: \"%s\" (%d) = " U64T " - " U64T "\n", pme->name, pme->pet, pme->base, pme->end);
    }

    fclose(f);
    free(cur_fname);
    free(mapspath);
    free(fname);

    return pme_head;
}


ProcMapsEntry *pme_walk(ProcMapsEntry *pme_head, ProcELFType pet) {
    ProcMapsEntry *pme = pme_head;
    while (pme) {
        if (pme->pet == pet) break;
        pme = pme->_next;
    }
    return pme;
}


ProcMapsEntry *pme_find_addr(ProcMapsEntry *pme_head, uint64_t addr) {
    ProcMapsEntry *pme = pme_head;
    while(pme) {
        if (addr >= pme->base && addr < pme->end) break;
        pme = pme->_next;
    }
    return pme;
}



uint64_t get_auxv_entry(int pid) {
    char *auxvpath = malloc(MAX_PATH_SIZE + 1);
    snprintf(auxvpath, MAX_PATH_SIZE, "/proc/%d/auxv", pid);
    FILE *f = fopen(auxvpath, "r");
    ASSERT(f, "failed to open auxiliary vector file %s: %s (%d)\n", auxvpath, strerror(errno), errno);

    unsigned long at_type;
    unsigned long at_value;
    unsigned long retval = 0;
    while (1) {
        if (!fread(&at_type, sizeof at_type, 1, f)) break;
        if (!fread(&at_value, sizeof at_value, 1, f)) break;
        //debug("AT_ENTRY=%lu, at_type=%lu, at_value=%lu\n", AT_ENTRY, at_type, at_value);
        if (at_type == AT_ENTRY) {
            retval = at_value;
            break;
        }
    }

    fclose(f);
    free(auxvpath);
    return retval;
}
