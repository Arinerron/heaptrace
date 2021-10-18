#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <sys/mman.h>
#include <inttypes.h>
#include <string.h>

#include "funcid.h"
#include "logging.h"


uint64_t search_fs(uint8_t *buf, size_t sz, funcsig fs) {
    uint8_t target = 0xff;
    uint8_t target2 = 0x00;

    uint8_t *first_byte_that_matters_pos = (uint8_t *)memmem(fs.undef, FUNCSIG_SZ, &target2, 1);
    if (!first_byte_that_matters_pos) return 0; // none of the bytes matter which means we match the first try
    size_t first_byte_offset = first_byte_that_matters_pos - fs.undef;
    uint8_t first_byte = *(fs.data + first_byte_offset);


    size_t curpos = 0;
    uint8_t *ptr = 0;
    while (1) {
        //if (curpos > 20) printf("curpos: %d, ptr: %p\n", curpos, ptr);
        if (!ptr) {
            ptr = buf;
            goto resetsearch;
        }
        
        uint8_t curbyte1 = fs.data[curpos];
        uint8_t curbyte2 = *(ptr + curpos);
        uint8_t curundef = fs.undef[curpos];
        if (curundef != 0xff) {
            // this byte matters. we have to check.
            //if (curpos > 20) printf("1: %x, 2: %x (undef: %x)\n", curbyte1, curbyte2, curundef);
            if (curbyte1 != curbyte2) goto resetsearch;
        }

        if (++curpos == FUNCSIG_SZ) {
            // we found it!
            //printf("found sol. ptr: %p. offset: %" PRIu64 "\n", ptr, ptr - buf);
            return (uint64_t)(ptr - buf);
        } else continue;

resetsearch:
        ptr += curpos + 1;
        curpos = 0;
        ptr = memmem(ptr, (buf + sz) - ptr, &first_byte, 1);
        if (!ptr) return 0;
        ptr -= first_byte_offset;
    }
    return 0;
}


// returns a malloc()'d array of size 5
FunctionSignature *find_function_signatures(FILE *f) {
    if (fseek(f, 0, SEEK_END)) {
        fclose(f);
        warn("failed to seek sig file target");
        return 0;
    }

    size_t filesize = ftell(f);
    fseek(f, 0, SEEK_SET);

    uint8_t *buf = (uint8_t *)mmap(0, (size_t)filesize, PROT_READ, MAP_PRIVATE, fileno(f), 0);
    if (buf == 0) {
        fclose(f);
        warn("mmap() failed in lookup_symbols");
        return 0;
    }

    FunctionSignature *sigs = (FunctionSignature *)calloc(5, sizeof(FunctionSignature));
    sigs[0].name = "malloc";
    sigs[1].name = "free";
    sigs[2].name = "calloc";
    sigs[3].name = "realloc";
    sigs[4].name = "reallocarray";
    const funcsig *fss_r[5] = {FUNCSIGS_MALLOC, FUNCSIGS_FREE, FUNCSIGS_CALLOC, FUNCSIGS_REALLOC, FUNCSIGS_REALLOCARRAY};
    const int fss_c[5] = {FUNCSIGS_MALLOC_COUNT, FUNCSIGS_FREE_COUNT, FUNCSIGS_CALLOC_COUNT, FUNCSIGS_REALLOC_COUNT, FUNCSIGS_REALLOCARRAY_COUNT};
    
    for (int j = 0; j < 5; j++) {
        FunctionSignature *sig = &sigs[j];

        const funcsig *fss = fss_r[j];
        int fssc = fss_c[j];
        int i = 0;
        while (1) {
            funcsig fs = fss[i++];
            sig->offset = search_fs(buf, filesize, fs);
            if (sig->offset) {
                break;
            }
            if (i == fssc) break;
        }

        //printf("(1) -> %s (%p) - %x (%p)\n", sig->name, sig, sig->offset, sig->offset);
        if (sig->offset) {
            debug("funcid identified sym \"%s\" at offset " U64T " (i=%d)\n", sig->name, sig->offset, i);
        }
    }

    return sigs;
}

/*int main(int argc, char *argv[]) {
    FILE *f = fopen(argv[1], "r");
    find_function_signatures(f);
    fclose(f);
    return 0;
}*/
