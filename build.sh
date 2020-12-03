#!/bin/sh

# someone plz make PR to add Makefile. I do not understand Makefiles
gcc -Wall -fPIC -DPIC -c -g -O3 heaptrace.c
ld -shared -o heaptrace.so heaptrace.o -ldl
