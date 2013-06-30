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
#include <libudis86/extern.h>
#include <libudis86/types.h>
#include "trace.h"
#include "ptrace.h"
#include "resolv.h"

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

	if ((child = fork()) == 0) {
		if (ptrace_traceme() < 0) {
			puts("[!] ptrace_traceme failed!");
			exit(1);
		}
		if (execv(tracee.prog, tracee.prog_args) == -1) {
			printf("[!] execv() failed (%s)\n", strerror(errno));
		}
		exit(1);
	}

	return child;
}

static void _dump_regs(const struct user_regs_struct *regs)
{
	/* Displays register information */
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_eax), regs->reg_eax);
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_ebx), regs->reg_ebx);
	printf("%s=0x%" ADDR_FMT " \n", STRFY(reg_ecx), regs->reg_ecx);
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_edx), regs->reg_edx);
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_esi), regs->reg_esi);
	printf("%s=0x%" ADDR_FMT " \n", STRFY(reg_edi), regs->reg_edi);
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_esp), regs->reg_esp);
	printf("%s=0x%" ADDR_FMT " | ", STRFY(reg_ebp), regs->reg_ebp);
	printf("%s=0x%" ADDR_FMT " \n", STRFY(reg_eip), regs->reg_eip);
}

static void _dump_stack(const struct user_regs_struct *regs)
{
	long addr;
	int i;

	/* Displays 4 long from the top of stack */
	printf("Stack:\n0x%" ADDR_FMT " [ ", regs->reg_esp);
	for (i = 0; i < 4; ++i) {
		ptrace_read_long(tracee.pid, regs->reg_esp + (i * sizeof(long)), &addr);
		printf("0x%" ADDR_FMT " ", addr);
	}
	printf("] 0x%" ADDR_FMT "\n", regs->reg_ebp);
}

static char* _instr_comments(ud_t *ud_obj,
	const struct user_regs_struct *regs)
{
	const char *instr = ud_insn_asm(ud_obj);
	char *comment = NULL;

	if (memcmp(instr, "syscall", sizeof("syscall")-1) == 0
		|| memcmp(instr, "int $0x80", sizeof("int $0x80")-1) == 0) {
		/* system call */
		comment = malloc(sizeof(char) * 50);
		snprintf(comment, 50, " # %s = %ld", STRFY(reg_eax), regs->reg_eax);
	} else if (memcmp(instr, "ret", sizeof("ret")-1) == 0) {
		/* return */
		long retaddr;

		comment = malloc(sizeof(char) * 50);
		ptrace_read_long(tracee.pid, regs->reg_esp, &retaddr);

		snprintf(comment, 50, " # 0x%" ADDR_FMT, retaddr);
	}
	return comment;
}

static void _dump_instr(const struct user_regs_struct *regs)
{
	unsigned char instrs[16] = {0};
	char *comment = NULL;
	long value;
	ud_t ud_obj;
	int i;
	uintptr_t addr = regs->reg_eip;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);
	ud_set_vendor(&ud_obj, UD_VENDOR_AMD);
	ud_set_pc(&ud_obj, regs->reg_eip);
	ud_set_syntax(&ud_obj, tracee.syntax ? UD_SYN_INTEL : UD_SYN_ATT);
	ud_set_input_buffer(&ud_obj, instrs, sizeof(instrs)-1);

	for (i = 0; i < sizeof(instrs) / sizeof(long); i += sizeof(long)) {
		ptrace_read_long(tracee.pid, regs->reg_eip + (sizeof(long) * i), &value);
		memcpy(instrs + (sizeof(long) * i), &value, sizeof(long));
	}

	if (tracee.flags & SHOW_REGISTERS) {
		_dump_regs(regs);
	}

	if (tracee.flags & SHOW_STACK) {
		_dump_stack(regs);
	}

	ud_disassemble(&ud_obj);

	if (tracee.flags & SHOW_COMMENTS) {
		comment = _instr_comments(&ud_obj, regs);
	}

	printf("%#" PRIxPTR ":\t%-20s\t%s%s\n",
		addr, ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj), comment ? comment : "");

	if (comment) {
		free(comment);
	}
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
				_dump_instr(&regs);
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
