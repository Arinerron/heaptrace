#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "logging.h"
#include "options.h"
#include "heap.h"
#include "debugger.h"

char *symbol_defs_str = "";

static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    
    {"debug", no_argument, NULL, 'D'}, // hidden, for dev use only
    
    {"environment", required_argument, NULL, 'e'},
    {"environ", required_argument, NULL, 'e'},
    
    {"break", required_argument, NULL, 'b'},
    {"break-at", required_argument, NULL, 'b'},
    
    {"break-after", required_argument, NULL, 'B'},

    {"symbols", required_argument, NULL, 's'},
    {"syms", required_argument, NULL, 's'},
    {"symbol", required_argument, NULL, 's'},
    
    {"follow-fork", no_argument, NULL, 'F'},
    {"follow", no_argument, NULL, 'F'},

    {"output", required_argument, NULL, 'o'},

    {NULL, 0, NULL, 0}
};


static void exit_failure(char *argv[]) {
    fprintf(stderr, "Usage: %s [-v] [-e/--environment <name=value>] [-b/--break <number>] [-B/--break-after <number>] [-s/--symbols <sym_defs>] [-F/--follow-fork] [-o/--output <filename>] -- <target> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
}


static uint64_t _parse_oid(char *optarg) {
    char *endp;
    while (*optarg == '#' || *optarg == ' ' || *optarg == '\n') optarg++;
    return strtoul(optarg, &endp, 10);
}


static uint64_t parse_bp(char *optarg) {
    if (!strcmp(optarg, "main") || !strcmp(optarg, "entry") || !strcmp(optarg, "start") || !strcmp(optarg, "_start")) {
        BREAK_MAIN = 1;
    } else if (!strcmp(optarg, "sigsegv") || !strcmp(optarg, "segv") || !strcmp(optarg, "error") || !strcmp(optarg, "abort") || !strcmp(optarg, "segfault")) {
        BREAK_SIGSEGV = 1;
    } else {
        return _parse_oid(optarg);
    }
}


// returns the index of the first non-argument in argv
int parse_args(int argc, char *argv[]) {
    bool isCaseInsensitive = false;
    int opt;

    extern char **environ;
    while ((opt = getopt_long(argc, argv, "vFDe:s:b:B:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v': {
                OPT_VERBOSE = 1;
                break;
            }

            case 'D': {
                OPT_DEBUG = 1;
                OPT_VERBOSE = 1;
                break;
            }

            case 's': {
                symbol_defs_str = (char *)optarg;
                break;
            }

            case 'e': {
                char *_eq = strstr(optarg, "=");
                if (!_eq) {
                    setenv(optarg, "", 1);
                } else {
                    *_eq = '\x00';
                    char *val = _eq + 1;
                    setenv(optarg, val, 1);
                }
                break;
            }

            case 'b': {
                BREAK_AT = parse_bp(optarg);
                break;
            }

            case 'B': {
                BREAK_AFTER = parse_bp(optarg);
                break;
            }

            case 'F': {
                OPT_FOLLOW_FORK = 1;
                break;
            }

            case 'o': {
                FILE *_output_file = fopen(optarg, "a+");
                if (!_output_file) {
                    fatal("failed to open logging file \"%s\".\n", optarg);
                    exit_failure(argv);
                } else {
                    output_fd = _output_file;
                }
                break;
            }

            default: {
                exit_failure(argv);
            }
        }
    }

    if (optind == argc) {
        fatal("you must specify a binary to execute.\n");
        exit_failure(argv);
    }

    return optind;
}


void evaluate_symbol_defs(Breakpoint **bps, int bpsc, ProcMapsEntry *pme_head) {
    if (!strlen(symbol_defs_str)) return;

    ProcMapsEntry *bin_pme = pme_walk(pme_head, PROCELF_TYPE_BINARY);
    ProcMapsEntry *libc_pme = pme_walk(pme_head, PROCELF_TYPE_LIBC);
    ASSERT(bin_pme, "Target binary is missing from process mappings (!bin_pme in evaluate_symbol_defs). Please report this!");
    uint64_t bin_base = 0;
    uint64_t libc_base = 0;
    if (bin_pme) bin_base = bin_pme->base;
    if (libc_pme) libc_base = libc_pme->base;

    char *orig_str = strdup(symbol_defs_str);
    size_t orig_str_len = strlen(orig_str);
    char *buf = malloc(orig_str_len + 1);
    memset(buf, '\x00', orig_str_len + 1);

    char *sym_name = orig_str;
    uint64_t sym_val = 0;
    char _sym_sign = '+';
    int _next_is_sym_name = 0;
    int _cur_step = 1;

    int j = 0;
    for (int i = 0; i < orig_str_len + 1; i++) {
        char c;
        if (i == orig_str_len) {
            // we're done! just parse what we have now
            c = '\x00';
            goto parsevalue;
        }

        c = orig_str[i];
        
        if (c == ' ' || c == '\n' || c == '\t') {
            // skip whitespace
            continue;
        } else {
            if (_next_is_sym_name) {
                _next_is_sym_name = 0;
                sym_name = orig_str + i;
            }

            if (c == '=') {
                // store the sym name
                _cur_step = 2; // now we're copying the value
                orig_str[i] = '\x00';
                sym_val = 0;
                _sym_sign = '+';
                continue;
            } else if (c == '-' || c == '+' || c == ',' || c == ';') {
parsevalue:;
                uint64_t val = 0;
                if (strcmp(buf, "libc") == 0) val = libc_base;
                else if (strcmp(buf, "bin") == 0) val = bin_base;
                else {
                    int base = 10;
                    if (buf[0] == '0') {
                        if (buf[1] == 'x') {
                            base = 16;
                        } else if (buf[1] == 'o') {
                            base = 8;
                        } else if (buf[1] == 'b') {
                            base = 2;
                        }
                    }
                    
                    char *_ptr;
                    val = strtoull(buf, &_ptr, base);
                }

                if (_sym_sign == '+') sym_val += val;
                if (_sym_sign == '-') sym_val -= val;

                if (c == '+' || c == '-') _sym_sign = c;
                else if (c == ',' || c == ';' || c == '\x00') {
                    debug("parsed arg sym \"%s\" to %p\n", sym_name, sym_val);
                    int _resolved = 0;
                    // terminate cur var setting
                    for (int k = 0; k < bpsc; k++) {
                        Breakpoint *bp = bps[k];
                        //printf("sym_name: %s, bp_name: %s\n", sym_name, bp->name);
                        if (!strcmp(sym_name, bp->name)) {
                            if (!_resolved) {
                                // symbol resolved!
                                bp->addr = sym_val;
                                _resolved = 1;
                            } else {
                                warn("two Breakpoint's are named \"%s\", please report this.\n", sym_name);
                            }
                        } else {
                            if (_resolved && bp->addr == sym_val) {
                                warn("two different breakpoints share the same address (\"%s\" and \"%s\"). Unexpected behavior will occur.\n", sym_name, bp->name);
                            }
                        }
                    }

                    if (!_resolved) {
                        warn("unable to resolve configured symbol name \"%s\" (address %p), ignoring...\n", sym_name, sym_val);
                    }

                    _next_is_sym_name = 1; // because we want to ignore whitespace
                    _cur_step = 1; // now we're copying the name
                }

                j = 0;
                goto resetbuf;
            } else {
                if (_cur_step == 2) { // only copy the val
                    buf[j++] = c;
                }
            }
        }

        continue;
resetbuf:
        memset(buf, '\x00', orig_str_len + 1);
    }

    free(buf);
    free(orig_str);
}

