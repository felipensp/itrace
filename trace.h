/*
 * itrace
 *
 * Trace specific routines header
 *
 */

#ifndef ITRACE_TRACE_H
#define ITRACE_TRACE_H

#include <sys/types.h>
#include <sys/user.h>
#include <stdint.h>

#define STRFY(x)  STRFY2(x)
#define STRFY2(x) #x

#if defined(__x86_64__)
# define ADDR_FMT "016lx"
# define reg_eip rip
# define reg_eax rax
# define reg_ebx rbx
# define reg_ecx rcx
# define reg_edx rdx
# define reg_edi rdi
# define reg_esi rsi
# define reg_esp rsp
# define reg_ebp rbp
#else
# define ADDR_FMT "08x"
# define reg_eip eip
# define reg_eax eax
# define reg_ebx ebx
# define reg_ecx ecx
# define reg_edx edx
# define reg_edi edi
# define reg_esi esi
# define reg_esp esp
# define reg_ebp ebp
#endif

typedef struct {
	const char *prog;   /* program to start and trace */
	char * const * prog_args;
	pid_t pid;             /* pid of tracee program */
	uintptr_t offset;      /* eip offset to start tracing */
	unsigned int num_inst; /* Max number of instruction to trace */
	int show_regs;         /* Indicates if the registers should be dumped */
	int show_stack;        /* Indicates if the stack must be dumped */
} trace_info;

pid_t trace_pid();
pid_t trace_program();
void trace_loop();

extern trace_info tracee;

#endif /* ITRACE_TRACE_H */
