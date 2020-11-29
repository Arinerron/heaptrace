#!/bin/sh

gcc -Wall -fPIC -DPIC -c htrace.c
ld -shared -o htrace.so htrace.o -ldl
