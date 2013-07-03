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

/*
 * Possible flags passed to itrace
 */
typedef enum {
	SHOW_REGISTERS = 1<<0, /* -r */
	SHOW_STACK     = 1<<1, /* -s */
	SHOW_COMMENTS  = 1<<2, /* -C */
	SHOW_MAPS      = 1<<3, /* -m */
	IGNORE_LIBS    = 1<<4  /* -i */
} trace_flags;

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
	int flags;                /* Flags to handle options                     */
} trace_info;

pid_t trace_pid();
pid_t trace_program();
void trace_loop();

extern trace_info tracee;

#endif /* ITRACE_TRACE_H */
