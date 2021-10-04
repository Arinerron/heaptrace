#include <malloc.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(0x100);
    malloc(0x100);
    malloc(0x100);
    free(ptr);
}
