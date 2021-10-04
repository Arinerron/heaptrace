#include <malloc.h>
#include <stdlib.h>

int main() {
    void *ptr = malloc(0x100);
    void *ptr2 = malloc(0x100);
    void *ptr3 = malloc(0x100);
    free(ptr2);
    free(0);
    free(ptr3);
    free(ptr2);
    free(ptr);
}
