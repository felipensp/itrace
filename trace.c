/*
 * itrace
 *
 * Trace specific routines
 *
 */

#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <libudis86/extern.h>
#include <libudis86/types.h>
#include "trace.h"
#include "ptrace.h"

pid_t trace_pid(pid_t pid)
{
	printf("[+] Attaching to pid %d\n", pid);

	if (ptrace_attach(pid) < 0) {
		puts("[!] ptrace_attach failed!");
		exit(1);
	}

	return pid;
}

pid_t trace_program(const char *program)
{
	return 0;
}

void trace_dump_instr(const struct user_regs_struct *regs)
{
	unsigned char instrs[16] = {0};
	long value;
	ud_t ud_obj;
	int i;
	uintptr_t addr = regs->reg_eip;

	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, 64);
	ud_set_vendor(&ud_obj, UD_VENDOR_AMD);
	ud_set_pc(&ud_obj, 0);
	ud_set_syntax(&ud_obj, UD_SYN_ATT);
	ud_set_input_buffer(&ud_obj, instrs, sizeof(instrs)-1);

	for (i = 0; i < sizeof(instrs) / sizeof(long); i += sizeof(long)) {
		ptrace_read(tracee.pid, regs->reg_eip, &value);
		memcpy(instrs + (sizeof(long) * i), &value, sizeof(long));
	}

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

	/* Displays three instructions after eip */
	ud_disassemble(&ud_obj);

	printf("%#" PRIxPTR ":\t%-15s\t%s\n",
		addr, ud_insn_hex(&ud_obj), ud_insn_asm(&ud_obj));
}

void _trace_abort_execution()
{
	printf("[!] Detaching...\n");
	ptrace_detach(tracee.pid);
	exit(0);
}

void trace_loop()
{
	int status, signo = 0, active = (tracee.offset == 0);
	unsigned int counter = 0;
	siginfo_t si;
	struct user_regs_struct regs;

	memset(&si, 0, sizeof(siginfo_t));

	signal(SIGINT, _trace_abort_execution);

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
		} else if (signo == SIGHUP || signo == SIGINT) {
			ptrace(PTRACE_CONT, tracee.pid, 0, signo);
			break;
		}

		ptrace(PTRACE_GETREGS, tracee.pid, NULL, &regs);
		ptrace(PTRACE_GETSIGINFO, tracee.pid, NULL, &si);

		if (!active) {
			active = (tracee.offset == regs.reg_eip);
		}

		if (active) {
			++counter;

			trace_dump_instr(&regs);

			if (counter == tracee.num_inst) {
				break;
			}
		}
	}
}
