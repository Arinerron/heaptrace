# About

heaptrace is a `ptrace`-based debugger similar to `ltrace` for tracking glibc heap operations (`malloc`, `calloc`, `free`, `realloc`, `reallocarray`) in ELF64 (x86-64) binaries. It is useful for debugging binaries and doing heap pwn.

![screenshot.png](screenshot.png)

* Prints out heap operations using symbols instead of pointers. This allows users to understand what is going on on the heap without having to compare pointer values at each operation.
* Detects some forms of heap corruption, double free vulnerabilities, and memory leakage issues.
* Allows users to set "breakpoints" at any heap operation number (`oid`). When heaptrace reaches the requested `oid` number, it immediately detaches itself from the tracee (the target binary) and attaches the GNU debugger (gdb). This allows users to easily debug the heap interactively at any point.

# Installation
## Official Releases

See the .deb and .rpm release files, and a pre-compiled binary at the [Releases page](https://github.com/Arinerron/heaptrace/releases/).

## Arch User Repository (PKGBUILD)

Use your preferred AUR helper to install the [`heaptrace-git`](https://aur.archlinux.org/packages/heaptrace-git/) package.

```
$ trizen -S heaptrace-git
```

## Compile from Source

```sh
$ git clone https://github.com/Arinerron/heaptrace.git && cd heaptrace
$ make
$ sudo make install
...
$ heaptrace ./target
```

# Usage

You can specify arguments to heaptrace before specifying the binary name:

```
Usage: heaptrace [-v] [-e/--environment <name=value>] [-b/--break-at <oid>] [-s/--symbols <sym_defs>] [-o/--output <filename>] <target> [args...]

-e <environ>, --environment=<environ>
                            Sets a single environmental variable. Useful for 
                            setting runtime settings for the target such as 
                            LD_PRELOAD=./libc.so.6 without having them affect 
                            heaptrace's runtime configuration.

-s <defs>, --symbols=<defs> Override the values heaptrace detects for the 
                            malloc/calloc/free/realloc/reallocarray symbols. 
                            If the binary is stripped, this argument is 
                            required to use heaptrace. See the wiki for more 
                            info.

-b <oid>, --break-at=<oid>  Send SIGSTOP to the process at heap operation 
                            specified in `oid` and attach the GNU debugger 
                            (gdb) to the process.

-o <file>, --output=<file>  Write the heaptrace output to `file` instead of 
                            stderr (default).

-v, --verbose               Print verbose information such as line numbers in
                            source code given the required debugging info is
                            stored in the ELF.
```

For example, if you wanted to automatically attach gdb at operation #3, you would execute:

```
heaptrace --break-at=3 ./my-binary
```

![screenshot-break.png](screenshot-break.png)

See the [wiki documentation](https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary) for more information on how to use the `-s`/`--symbol` argument to debug stripped binaries.

# Support

I'm happy to help if you experience a bug or have any feedback. Please see the [GitHub Issues](https://github.com/Arinerron/heaptrace/issues) page.

