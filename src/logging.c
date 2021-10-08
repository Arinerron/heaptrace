#include "logging.h"

FILE *output_fd;
int OPT_DEBUG = 0;

// TODO: convert to elf parsing
/*void describe_symbol(void *ptr) {
    Dl_info ptrinfo;
    if (!OPT_VERBOSE) return;
    dladdr(ptr, &ptrinfo);

    if (ptrinfo.dli_sname && ptrinfo.dli_fname) {
        // symbol found
        log("\t(%s%s%s in %s%s%s)", BOLD(ptrinfo.dli_sname), BOLD(ptrinfo.dli_fname));
    }
}
*/
