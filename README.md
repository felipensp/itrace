itrace
======

Tracks runtime instruction execution in programs

Requirements: libudis86

Author: Felipe Pena
Contact: felipensp [at] gmail [dot] com


Usage:
```
itrace [options]
-c, --command     Program to be started and traced
-C, --comments    Show comments after disassembled instruction
-h, --help        Show this help
-n, --max-inst    Max number of instruction to trace
-o, --offset      Address to start tracing
-p, --pid         Attach to supplied pid
-r, --show-regs   Dump registers on each instruction
-s, --show-stack  Dump part of stack from top on each instruction
-S, --syntax      Choose the syntax to be used on disassemble
-v, --version     Show the version

```

Example:

```
$ ./itrace -o 0x400589 -s -c ../overflow1 CBBBBBBBBAAAAAAAA
[+] Starting and tracing `../overflow1'
Arg[0]: ../overflow1
Arg[1]: CBBBBBBBBAAAAAAAA
Stack:
0x00007ffffab95b20 [ 0x00007ffffab95c28 0x0000000200400440 0x00007ffffab95c20 0x4300000000000000 ] 0x00007ffffab95b40
0x400589:	c9                  	leave
Stack:
0x00007ffffab95b48 [ 0x4141414141414141 0x0000000000000000 0x00007ffffab95c28 0x0000000200000000 ] 0x4242424242424242
0x40058a:	c3                  	ret
[!] Program exited with status 11

```
