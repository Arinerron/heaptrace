#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "logging.h"
#include "options.h"
#include "heap.h"

int args_parsed_yet = 0;
int OPT_BREAK = 0;
int OPT_VERBOSE = 0;

static struct option long_options[] = {
    {"verbose", no_argument, NULL, 'v'},
    {"break-at", required_argument, NULL, 'b'},
    {"output", required_argument, NULL, 'o'},
    {NULL, 0, NULL, 0}
};


static void exit_failure(char *argv[]) {
    fprintf(stderr, "Usage: %s [-v] [-b/--break-at <oid>] [-o/--output <filename>] <binary> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
}


// returns the index of the first non-argument in argv
int parse_args(int argc, char *argv[]) {
    bool isCaseInsensitive = false;
    int opt;

    // reset break-ats array
    for (int i = 0; i < MAX_BREAK_ATS; i++) {
        break_ats[i] = 0;
    }

    while ((opt = getopt_long(argc, argv, "vb:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'v':
                OPT_VERBOSE = 1;
                break;
            case 'b':
                char *endp;
                int break_at = strtoul(optarg, &endp, 10);
                for (int i = 0; i < MAX_BREAK_ATS; i++) {
                    if (!break_ats[i]) {
                        break_ats[i] = break_at;
                        break;
                    }
                }
                break;
            case 'o':
                FILE *_output_file = fopen(optarg, "a+");
                if (!_output_file) {
                    fprintf(stderr, "Failed to open logging file \"%s\".\n", optarg);
                    exit_failure(argv);
                } else {
                    output_fd = _output_file;
                }
                break;
            default:
                exit_failure(argv);
        }
    }

    if (optind == argc) {
        fprintf(stderr, "You must specify a binary to execute.\n");
        exit_failure(argv);
    }

    return optind;
}
