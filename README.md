# About

heaptrace is an `LD_PRELOAD`-based tool similar to ltrace that is made for tracking heap operations (malloc, free, realloc). It is useful for debugging binaries and doing heap pwn.

![screenshot.png](screenshot.png)

It allows users to set breakpoints at heap operations, and is able to automatically identify and describe both double free vulnerabilities and memory leakage issues.

## Setup

```sh
$ git clone https://github.com/Arinerron/heaptrace && cd heaptrace
$ ./build.sh
...
$ LD_PRELOAD=./heaptrace.so ./my-binary
```

## Usage

You can specify additional arguments using the `HEAPTRACE_ARGS` environmental variable.

```
-o <file>, --output=<file>  Write the heaptrace output to `file` instead of 
                            stderr (default).

-b <oid>, --break-at=<oid>  Send SIGSTOP to the process at heap operation 
                            specified in `oid` and print instructions to gdb
                            attach to the process.

--break                     Send SIGSTOP to the process on every heap 
                            operation and print instructions to gdb attach.

-v, --verbose               Print verbose information such as line numbers in
                            source code given the required debugging info is
                            stored in the ELF.
```

For example, if you wanted to attach gdb at operation #6, you would execute:

```
$ LD_PRELOAD=./heaptrace.so HEAPTRACE_ARGS="-b 6" ./my-binary
```

![screenshot-break.png](screenshot-break.png)

