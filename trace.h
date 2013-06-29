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

/*
 * Helper macro to handle user_regs_struct's field names
 * based on the architecture
 */
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

/*
 * Flags to handle option related to what to show on the trace
 */
typedef enum {
	SHOW_REGISTERS = 1<<0,
	SHOW_STACK     = 1<<1,
	SHOW_COMMENTS  = 1<<2
} trace_show_opts;

/*
 * General information of tracee and argument options
 */
typedef struct {
	const char *prog;         /* program to start and trace                  */
	char * const *prog_args;  /* program arguments                           */
	pid_t pid;                /* pid of tracee program                       */
	uintptr_t offset;         /* eip offset to start tracing                 */
	unsigned int num_inst;    /* Max number of instruction to trace          */
	int syntax;               /* Assembly syntax (0 = at&t, 1 = intel)       */
	int flags;                /* Flags to handle options to show information */
} trace_info;

pid_t trace_pid();
pid_t trace_program();
void trace_loop();

extern trace_info tracee;

#endif /* ITRACE_TRACE_H */
