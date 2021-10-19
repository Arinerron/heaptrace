# About

heaptrace is a heap debugger for tracking glibc heap operations in ELF64 (x86_64) binaries. Its purpose is to help visualize heap operations when debugging binaries or doing heap pwn.

![screenshot.png](screenshot.png)

* Prints out heap operations using symbols instead of pointers. This allows users to understand what is going on on the heap without having to compare pointer values at each operation.
* Detects some forms of heap corruption, double free vulnerabilities, and memory leakage issues.
* Allows users to set "breakpoints" at any heap operation via `--break <number>` and `--break-after <number>`. When heaptrace reaches the requested heap operation number number, it immediately detaches itself from the tracee (the target binary) and attaches the GNU debugger (gdb). This allows users to easily debug the heap interactively at any point.
* Automatically resolves symbols if available. If the binary is stripped, it attempts to automatically identify function offsets based on function signatures.

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
Usage:
  heaptrace [options...] <target> [args...]
  heaptrace [options...] --attach <pid>

Options:
  -e <name=value>, --environ=<name=value>, --environment=<name=value>
	 Sets a single environmental variable. Useful for 
	 setting runtime settings for the target such as 
	 LD_PRELOAD=./libc.so.6 without having them affect 
	 heaptrace's runtime configuration.


  -s <sym_defs>, --symbols=<sym_defs>
	 Override the values heaptrace detects for the 
	 malloc/calloc/free/realloc/reallocarray symbols. 
	 Useful if heaptrace fails to automatically 
	 identify heap functions in a stripped binary. See 
	 the wiki for more info.


  -b <number>, --break=<number>, --break-at=<number>
	 Send SIGSTOP to the process at heap operation 
	 specified in `number` (before executing the heap 
	 function) and attach the GNU debugger (gdb) to the 
	 process.

	 Also supports "segfault" in the `number` arg to 
	 launch gdb if the process exits abnormally 
	 (SIGSEGV, abort(), etc). And, "main" will break at 
	 the entry point to the binary (the process' 
	 AT_ENTRY auxiliary vector value).


  -B <number>, --break-after=<number>
	 Similar to `--break`. Replaces the tracer 
	 process with gdb, but only after the heap function 
	 returns.


  -F, --follow-fork, --follow
	 Tells heaptrace to detach the parent and follow 
	 the child if the target calls fork(), vfork(), or 
	 clone().

	 The default behavior is to detatch the child and 
	 only trace the parent.


  -G <path>, --gdb-path <path>
	 Tells heaptrace to use the path to gdb specified 
	 in `path` instead of /usr/bin/gdb (default).


  -p <pid>, --attach <pid>, --pid <pid>
	 Tells heaptrace to attach to the specified pid 
	 instead of running the binary from the `target` 
	 argument. Note that if you specify this argument 
	 you do not have to specify `target`.


  -o <file>, --output=<file>
	 Write the heaptrace output to `file` instead of 
	 /dev/stderr (which is the default output path).


  -v, --verbose
	 Prints verbose information such as line numbers in
	 source code given the required debugging info is
	 stored in the ELF.


  -h, --help
	 Shows this help menu.

```

For example, if you wanted to automatically attach gdb at operation #3, you would execute:

```
$ heaptrace --break=3 ./my-binary
```

See the [wiki documentation](https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary) for more information on how to use the `-s`/`--symbol` argument to debug stripped binaries that heaptrace failed to automatically identify functions in.

# Support

I'm happy to help if you experience a bug or have any feedback. Please see the [GitHub Issues](https://github.com/Arinerron/heaptrace/issues) page.

