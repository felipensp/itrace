/*
 * itrace
 *
 * ptrace specific routines
 *
 */

#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include "ptrace.h"
#include "trace.h"

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

void ptrace_read_long(pid_t pid, uintptr_t addr, void *vptr)
{
	ptrace_read(pid, addr, vptr, sizeof(long));
}

void ptrace_read(pid_t pid, uintptr_t addr, void *vptr, long len)
{
	const size_t long_size = sizeof(long);
	size_t i = 0, j = len / long_size, is_exact = len % long_size;
	long word;
	void *saddr = vptr;

	while (i <= j) {
		if (i == j && is_exact == 0) {
			break;
		}
		errno = 0;
		word = ptrace(PTRACE_PEEKTEXT, pid, addr + i * long_size, NULL);
		if (errno != 0) {
			iprintf("[!] PTRACE_PEEKTEXT failed (%s)\n", strerror(errno));
		}

		memcpy(saddr, &word, i == j ? (len % long_size) : long_size);
		saddr += long_size;
		++i;
	}
}

void ptrace_write(pid_t pid, uintptr_t addr, long value)
{
	if (ptrace(PTRACE_POKETEXT, pid, addr, value) == -1) {
		iprintf("[!] PTRACE_POKETEXT failed (%s)\n", strerror(errno));
	}
}
