#include <malloc.h>
#include <stdlib.h>


void asdf() {
    void *ptr2 = malloc(0x100);
    void *ptr3 = malloc(0x100);
    free(ptr2);
    free(0);
    free(ptr3);
}

int main() {
    void *ptr = malloc(0x100);
    asdf();
    asdf();
    asdf();
    free(ptr);
}
