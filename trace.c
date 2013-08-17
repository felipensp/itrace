/*
 * itrace
 *
 * Trace specific routines
 *
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include "trace.h"
#include "ptrace.h"
#include "resolv.h"
#include "elfsym.h"
#include "disas.h"

pid_t trace_pid()
{
	iprintf("[+] Attaching to pid %d\n", tracee.pid);

	if (ptrace_attach(tracee.pid) < 0) {
		iprintf("[!] ptrace_attach failed!\n");
		return 0;
	}

	return tracee.pid;
}

pid_t trace_program()
{
	pid_t child;
	int nargs;

	assert(tracee.prog != NULL);

	iprintf("[+] Starting and tracing `%s'\n", tracee.prog);

	for (nargs = 0; tracee.prog_args[nargs]; ++nargs) {
		iprintf("Arg[%d]: %s\n", nargs, tracee.prog_args[nargs]);
	}

	child = fork();

	if (child == 0) {
		/* child process */

		if (ptrace_traceme() < 0) {
			iprintf("[!] ptrace_traceme failed!\n");
			exit(1);
		}
		if (execv(tracee.prog, tracee.prog_args) == -1) {
			iprintf("[!] execv() failed (%s)\n", strerror(errno));
		}
		exit(1);
	} else if (child < 0) {
		iprintf("[!] fork() failed (%s)\n", strerror(errno));
		exit(1);
	}

	return child;
}

static void _abort_execution()
{
	iprintf("[!] Detaching...\n");
	ptrace_detach(tracee.pid);
	kill(tracee.pid, SIGINT);
	exit(1);
}

void trace_loop()
{
	int status, signo = 0, active = (tracee.offset == 0);
	unsigned int counter = 0, total = 0;
	struct user_regs_struct regs;

	signal(SIGINT, _abort_execution);
	resolv_startup();
	wait(&status);

	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, tracee.pid, NULL, signo) != 0) {
			iprintf("Error: ptrace() failed on single-stepping!\n");
			exit(1);
		}
		wait(&status);

		if (!WIFSTOPPED(status)) {
			break;
		}

		signo = WSTOPSIG(status);

		if (signo == SIGTRAP) {
			signo = 0;
		} else {
			switch (signo) {
				case SIGHUP:
				case SIGINT:
				case SIGSEGV:
					ptrace(PTRACE_CONT, tracee.pid, 0, signo);
					goto out;
				default:
					break;
			}
		}
		++total;
		ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs);

		if (!active) {
			active = (tracee.offset == regs.reg_eip);
		}

		if (active) {
			++counter;

			if ((tracee.flags & IGNORE_LIBS)
				&& resolv_is_dynamic(regs.reg_eip)) {
				continue;
			}

			if (tracee.num_inst == 0 || counter <= tracee.num_inst) {
				disas_instr(&regs);
			}
		}
	}
out:
	iprintf("[!] Program exited with status %d\n", WEXITSTATUS(status));

	if (tracee.flags & SHOW_MAPS) {
		resolv_show_maps();
	}
	
	if (tracee.flags & SHOW_COUNT) {
		printf("Instructions executed=%u\n", total);
	}

	resolv_shutdown();
}
