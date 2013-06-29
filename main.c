/*
 * itrace
 *
 * Main file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include "trace.h"

trace_info tracee;

static void usage()
{
	puts("itrace [options]\n"
		 "-c, --command     Program to be started and traced\n"
		 "-C, --comments    Show comments after disassembled instruction\n"
		 "-h, --help        Show this help\n"
		 "-n, --max-inst    Max number of instruction to trace\n"
		 "-o, --offset      Address to start tracing\n"
		 "-p, --pid         Attach to supplied pid\n"
		 "-r, --show-regs   Dump registers on each instruction\n"
		 "-s, --show-stack  Dump part of stack from top on each instruction\n"
		 "-v, --version     Show the version\n");
}

static void version()
{
	puts("itrace - version dev");
}

int main(int argc, char **argv)
{
	pid_t pid = 0;
	char c;
	int opt_index = 0;
	static struct option long_opts[] = {
		{"command",    required_argument, 0, 'c'},
		{"comments",   no_argument,       0, 'C'},
		{"help",       no_argument,       0, 'h'},
		{"max-inst",   required_argument, 0, 'n'},
		{"offset",     required_argument, 0, 'o'},
		{"pid",        required_argument, 0, 'p'},
		{"show-regs",  no_argument,       0, 'r'},
		{"show-stack", no_argument,       0, 's'},
		{"version",    no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};

	if (argc == 1) {
		usage();
		exit(0);
	}

	while ((c = getopt_long(argc, argv, "c:Chn:o:p:rsv", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				tracee.prog = optarg;
				tracee.prog_args = (char* const*)&argv[optind-1];
				break;

			case 'C':
				tracee.show_comments = 1;
				break;

			case 'h':
				usage();
				exit(0);

			case 'n':
				tracee.num_inst = atol(optarg);
				break;

			case 'o':
				sscanf(optarg, "%lx", &tracee.offset);
				break;

			case 'p':
				tracee.pid = atol(optarg);
				break;

			case 'r':
				tracee.show_regs = 1;
				break;

			case 's':
				tracee.show_stack = 1;
				break;

			case 'v':
				version();
				exit(0);
		}
	}

	if (pid) {
		tracee.pid = trace_pid();
	} else {
		tracee.pid = trace_program();
	}

	trace_loop();

	return 0;
}
