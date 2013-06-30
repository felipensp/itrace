/*
 * itrace
 *
 * ptrace specific routines header file
 *
 */

#ifndef ITRACE_PTRACE_H
#define ITRACE_PTRACE_H

#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <stdint.h>
#include <string.h>

long ptrace_attach(pid_t);
long ptrace_detach(pid_t);
long ptrace_traceme();
void ptrace_read_long(pid_t, uintptr_t, void*);
void ptrace_read(pid_t, uintptr_t, void*, long);
void ptrace_write(pid_t, uintptr_t, long);

#endif /* ITRACE_PTRACE_H */
