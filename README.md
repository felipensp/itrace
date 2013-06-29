itrace
======

Tracks runtime assembly instruction execution in programs


Usage:

```
$ itrace -s 0x40056a -n 3 -p 7607
[+] Attaching to pid 7582
rax=0x0000000000000000 | rbx=0x0000000000000000 | rcx=0xffffffffffffffff
rdx=0x0000000000000000 | rsi=0x00007fffd0b75e80 | rdi=0x00007fffd0b75e80
rsp=0x00007fffd0b75ec0 | rbp=0x00007fffd0b75ee0 | rip=0x000000000040056a
0x40056a:	488b45e0            	mov -0x20(%rbp), %rax
rax=0x00007fffd0b75fc8 | rbx=0x0000000000000000 | rcx=0xffffffffffffffff
rdx=0x0000000000000000 | rsi=0x00007fffd0b75e80 | rdi=0x00007fffd0b75e80
rsp=0x00007fffd0b75ec0 | rbp=0x00007fffd0b75ee0 | rip=0x000000000040056e
0x40056e:	4883c008            	add $0x8, %rax
rax=0x00007fffd0b75fd0 | rbx=0x0000000000000000 | rcx=0xffffffffffffffff
rdx=0x0000000000000000 | rsi=0x00007fffd0b75e80 | rdi=0x00007fffd0b75e80
rsp=0x00007fffd0b75ec0 | rbp=0x00007fffd0b75ee0 | rip=0x0000000000400572
0x400572:	488b10              	mov (%rax), %rdx
```
