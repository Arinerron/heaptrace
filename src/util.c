#include "util.h"
#include "context.h"

uint is_uint(char *str) {
    if (!str) return 0;
    while (*str) {
        if (!isdigit(*(str++))) return 0;
    }
    return 1;
}


uint is_uint_hex(char *str) {
    if (!str) return 0;
    while (*str) {
        if (!isxdigit(*(str++))) return 0;
    }
    return 1;
}


uint64_t str_to_uint64(char *buf) {
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
    return strtoull(buf, &_ptr, base);
}


void cleanup_and_exit(HeaptraceContext *ctx, int status) {
    free_ctx(ctx);
    free_user_breakpoints();
    exit(status);
}
