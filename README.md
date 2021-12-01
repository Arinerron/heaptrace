# About

heaptrace is a heap debugger for tracking glibc heap operations in ELF64 (x86\_64) binaries. Its purpose is to help visualize heap operations when debugging binaries or doing heap pwn.

![screenshot.png](screenshot.png)

* replaces addresses with easy-to-understand symbols
* detects heap corruption and memory leakage issues
* can debug in gdb at any point ([`--break`](https://github.com/Arinerron/heaptrace/wiki/How-to-Create-Breakpoints))
* supports all ELF64 (x86\_64) binaries regardless of ASLR or compiler settings ([including stripped binaries](https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary))

[How are heaptrace and valgrind different?](https://github.com/Arinerron/heaptrace/wiki/Difference-between-heaptrace-and-valgrind)

# Installation
## Official Releases

See the .deb and .rpm release files, and a pre-compiled binary at the [Releases page](https://github.com/Arinerron/heaptrace/releases/).

## Arch User Repository (PKGBUILD)

Use your preferred AUR helper to install one of the two following packages:
* [`heaptrace-git`](https://aur.archlinux.org/packages/heaptrace-git/) &mdash; source package ([PKGBUILD](https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=heaptrace-git))
* [`heaptrace`](https://aur.archlinux.org/packages/heaptrace/) &mdash; binary package ([PKGBUILD](https://aur.archlinux.org/cgit/aur.git/plain/PKGBUILD?h=heaptrace))

```
$ trizen -S heaptrace-git
... OR ...
$ trizen -S heaptrace
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
  -p <pid>, --attach <pid>, --pid <pid>
	 Tells heaptrace to attach to the specified pid 
	 instead of running the binary from the `target` 
	 argument. Note that if you specify this argument 
	 you do not have to specify `target`.


  -b <expression>, --break=<expression>, --break-at=<expression>
	 Send SIGSTOP to the process when the specified 
	 `expression` is satisfied and attach the GNU debugger 
	 (gdb) to the process.

	 This argument supports complex expressions. Please 
	 See the documentation for more information: 
	 https://github.com/Arinerron/heaptrace/wiki/How-to-Create-Breakpoints


  -B <expression>, --break-after=<expression>
	 Similar to `--break`. Replaces the tracer 
	 process with gdb, but only after the heap function 
	 returns. See the documentation for more information: 
	 https://github.com/Arinerron/heaptrace/wiki/How-to-Create-Breakpoints


  -e <name=value>, --environ=<name=value>, --environment=<name=value>
	 Sets a single environmental variable. Useful for 
	 setting runtime settings for the target such as 
	 LD_PRELOAD=./libc.so.6 without having them affect 
	 heaptrace's runtime configuration. This option can 
	 be used multiple times.

  -s <sym_defs>, --symbols=<sym_defs>
	 Override the values heaptrace detects for the 
	 malloc/calloc/free/realloc/reallocarray symbols. 
	 Useful if heaptrace fails to automatically 
	 identify heap functions in a stripped binary. See 
	 the wiki for more info.


  -F, --follow-fork, --follow
	 Tells heaptrace to detach the parent and follow 
	 the child if the target calls fork(), vfork(), or 
	 clone().

	 The default behavior is to detatch the child and 
	 only trace the parent.


  -G <path>, --gdb-path <path>
	 Tells heaptrace to use the path to gdb specified 
	 in `path` instead of /usr/bin/gdb (default).


  -w <width>, --width=<width>, --term-width=<width>
	 Force a certain terminal width.


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

* For example, if you wanted to automatically attach gdb at operation #3, you would execute `heaptrace --break=3 ./my-binary`. Please see the [wiki documentation](https://github.com/Arinerron/heaptrace/wiki/How-to-Create-Breakpoints) for more information on how to use this argument.
* See the [wiki documentation](https://github.com/Arinerron/heaptrace/wiki/Dealing-with-a-Stripped-Binary) for more information on how to use the `-s`/`--symbol` argument to debug stripped binaries that heaptrace failed to automatically identify functions in.
* Set the `$NO_COLOR` argument to remove ANSI color codes from output. This option is still in development and will be converted into an argument soon.

# Support

I'm happy to help if you experience a bug or have any feedback. Please see the [GitHub Issues](https://github.com/Arinerron/heaptrace/issues) page.

