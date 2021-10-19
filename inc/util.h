#ifndef UTIL_H
#define UTIL_H

#include "ctype.h"
#include "logging.h"

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define ABORT() exit(1)
#else
#define ABORT() abort()
#endif

#define ASSERT_NICE(q, msg, ...) if (!(q)) { fatal_heap("assertion (%s) failed in %s:%d: " msg, #q, __FILE__, __LINE__, ##__VA_ARGS__); }
#define ASSERT(q, msg, ...) if (!(q)) { \
        ASSERT_NICE(q, msg, ##__VA_ARGS__) \
        ABORT();  \
    }

#define PTRACE(...) { if (ptrace(__VA_ARGS__) == -1) { warn("ptrace call in %s:%d returned -1: %s (%d):\n\tptrace(%s)\n", __FILE__, __LINE__, strerror(errno), errno, (#__VA_ARGS__)); } }

uint is_uint(char *str);
uint64_t str_to_uint64(char *buf);

#endif
