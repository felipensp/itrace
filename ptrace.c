/*
 * itrace
 *
 * ptrace specific routines
 *
 */

#include <unistd.h>
#include "ptrace.h"

long ptrace_attach(pid_t pid)
{
	return ptrace(PTRACE_ATTACH, pid, NULL, NULL);
}

long ptrace_detach(pid_t pid)
{
	return ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

long ptrace_traceme()
{
	return ptrace(PTRACE_TRACEME, 0, NULL, NULL);
}

void ptrace_read(pid_t pid, uintptr_t addr, void *vptr)
{
	long word = ptrace(PTRACE_PEEKTEXT, pid, addr, NULL);
	memcpy(vptr, &word, sizeof(long));
}

void ptrace_write(pid_t pid, uintptr_t addr, long value)
{
	ptrace(PTRACE_POKETEXT, pid, addr, value);
}
