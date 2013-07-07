itrace
======

Tracks runtime instruction execution in programs

* Supported: ELF 32 and 64 bit (little-endian).
* Requirements: libudis86 (https://github.com/vmt/udis86)

Author: Felipe Pena (felipensp at gmail dot com)


###### Usage:
```
itrace [options]
-c, --command     Program to be started and traced
-C, --comments    Show comments after disassembled instruction
-h, --help        Show this help
-i, --ignore-libs Disable tracing of libraries segments
-I, --show-count  Show the number of instructions executed
-m, --maps        Show the maps file after execution
-n, --max-inst    Max number of instruction to trace
-o, --offset      Address to start tracing
-p, --pid         Attach to supplied pid
-q, --quiet       Do not show default output
-r, --show-regs   Dump registers on each instruction
-s, --show-stack  Dump part of stack from top on each instruction
-S, --syntax      Choose the syntax to be used on disassemble
-v, --version     Show the version
```

###### Example:

```
$ ./itrace -o 0x400584 -C -c ../overflow1 CBBBBBBBBAAAAAAAA
[+] Starting and tracing `../overflow1'
Arg[0]: ../overflow1
Arg[1]: CBBBBBBBBAAAAAAAA
0x400584:	b800000000          	mov $0x0, %eax
0x400589:	c9                  	leave
0x40058a:	c3                  	ret  # 0x4141414141414141
[!] Program exited with status 11
```
