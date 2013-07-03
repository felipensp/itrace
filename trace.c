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
	printf("[+] Attaching to pid %d\n", tracee.pid);

	if (ptrace_attach(tracee.pid) < 0) {
		puts("[!] ptrace_attach failed!");
		return 0;
	}

	return tracee.pid;
}

pid_t trace_program()
{
	pid_t child;
	int nargs;

	assert(tracee.prog != NULL);

	printf("[+] Starting and tracing `%s'\n", tracee.prog);

	for (nargs = 0; tracee.prog_args[nargs]; ++nargs) {
		printf("Arg[%d]: %s\n", nargs, tracee.prog_args[nargs]);
	}

	child = fork();

	if (child == 0) {
		/* child process */

		if (ptrace_traceme() < 0) {
			puts("[!] ptrace_traceme failed!");
			exit(1);
		}
		if (execv(tracee.prog, tracee.prog_args) == -1) {
			printf("[!] execv() failed (%s)\n", strerror(errno));
		}
		exit(1);
	} else if (child < 0) {
		printf("[!] fork() failed (%s)\n", strerror(errno));
		exit(1);
	}

	return child;
}

static void _abort_execution()
{
	printf("[!] Detaching...\n");
	ptrace_detach(tracee.pid);
	kill(tracee.pid, SIGINT);
	exit(1);
}

void trace_loop()
{
	int status, signo = 0, active = (tracee.offset == 0);
	unsigned int counter = 0;
	struct user_regs_struct regs;

	signal(SIGINT, _abort_execution);
	resolv_startup();
	wait(&status);

	while (1) {
		if (ptrace(PTRACE_SINGLESTEP, tracee.pid, NULL, signo) != 0) {
			puts("ptrace() failed on single-stepping!");
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
	printf("[!] Program exited with status %d\n", WEXITSTATUS(status));

	if (tracee.flags & SHOW_MAPS) {
		resolv_show_maps();
	}

	resolv_shutdown();
}
