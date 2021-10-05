#!/bin/sh

cd src
gcc -static \
    -o ../heaptrace \
    \
    logging.c \
    main.c \
    breakpoint.c \
    symbol.c \
    debugger.c \
    heap.c \
    options.c \
    handlers.c
