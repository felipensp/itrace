/*
 * itrace
 *
 * Main file
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include "trace.h"

trace_info tracee;

static void usage()
{
	puts("itrace [options]\n"
		 "-c, --command     Program to be started and traced\n"
		 "-C, --comments    Show comments after disassembled instruction\n"
		 "-h, --help        Show this help\n"
		 "-i, --ignore-libs Disable tracing of libraries segments\n"
		 "-I, --show-count  Show the number of instructions executed\n"
		 "-m, --maps        Show the maps file after execution\n"
		 "-n, --max-inst    Max number of instruction to trace\n"
		 "-o, --offset      Address to start tracing\n"
		 "-p, --pid         Attach to supplied pid\n"
		 "-q, --quiet       Do not show default output\n"
		 "-r, --show-regs   Dump registers on each instruction\n"
		 "-s, --show-stack  Dump part of stack from top on each instruction\n"
		 "-S, --syntax      Choose the syntax to be used on disassemble\n"
		 "-v, --version     Show the version\n");
}

static void version()
{
	puts("itrace - version dev");
}

int main(int argc, char **argv)
{
	char c;
	int opt_index = 0;
	static struct option long_opts[] = {
		{"command",    required_argument, 0, 'c'},
		{"comments",   no_argument,       0, 'C'},
		{"help",       no_argument,       0, 'h'},
		{"ignore-libs",no_argument,       0, 'i'},
		{"show-count", no_argument,       0, 'I'},
		{"show-maps",  no_argument,       0, 'm'},
		{"max-inst",   required_argument, 0, 'n'},
		{"offset",     required_argument, 0, 'o'},
		{"pid",        required_argument, 0, 'p'},
		{"quiet",      no_argument,       0, 'q'},
		{"show-regs",  no_argument,       0, 'r'},
		{"show-stack", no_argument,       0, 's'},
		{"syntax",     required_argument, 0, 'S'},
		{"version",    no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};

	if (argc == 1) {
		usage();
		exit(0);
	}

	while ((c = getopt_long(argc, argv, "c:ChiImn:o:p:qrsS:v", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				tracee.prog = optarg;
				tracee.prog_args = (char* const*)&argv[optind-1];
				goto out;

			case 'C':
				tracee.flags |= SHOW_COMMENTS;
				break;

			case 'h':
				usage();
				exit(0);

			case 'i':
				tracee.flags |= IGNORE_LIBS;
				break;
			
			case 'I':
				tracee.flags |= SHOW_COUNT;
				break;

			case 'm':
				tracee.flags |= SHOW_MAPS;
				break;

			case 'n':
				tracee.num_inst = atol(optarg);
				break;

			case 'o':
				sscanf(optarg, "%lx", &tracee.offset);
				break;

			case 'p':
				tracee.pid = atol(optarg);
				break;
			
			case 'q':
				tracee.flags |= QUIET_MODE;
				break;

			case 'r':
				tracee.flags |= SHOW_REGISTERS;
				break;

			case 's':
				tracee.flags |= SHOW_STACK;
				break;

			case 'S':
				if (strcasecmp(optarg, "intel") == 0) {
					tracee.syntax = 1;
				}
				break;

			case 'v':
				version();
				exit(0);
		}
	}
out:
	if (tracee.pid) {
		tracee.pid = trace_pid();
	} else {
		tracee.pid = trace_program();
	}

	if (tracee.pid) {
		trace_loop();
	}

	return 0;
}
