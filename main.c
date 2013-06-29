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
		 "-h, --help     Show this help\n"
		 "-n, --numinst  Max number of instruction to trace\n"
		 "-p, --pid      Attach to pid\n"
		 "-s, --start    Address to start tracing\n"
		 "-v, --version  Show the version\n");
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
		{"command", required_argument, 0, 'c'},
		{"help",    no_argument,       0, 'h'},
		{"numinst", required_argument, 0, 'n'},
		{"pid",     required_argument, 0, 'p'},
		{"start",   required_argument, 0, 's'},
		{"version", no_argument,       0, 'v'},
		{0, 0, 0, 0}
	};

	if (argc == 1) {
		usage();
		exit(0);
	}

	while ((c = getopt_long(argc, argv, "c:hn:p:s:v", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'h':
				usage();
				exit(0);

			case 'n':
				tracee.num_inst = atol(optarg);
				break;

			case 'p':
				pid = atol(optarg);
				break;

			case 's':
				sscanf(optarg, "%lx", &tracee.offset);
				break;

			case 'v':
				version();
				exit(0);
		}
	}

	if (pid) {
		tracee.pid = trace_pid(pid);
	} else {
		/*
		tracee.pid = trace_program(..);
		*/
	}

	trace_loop();

	return 0;
}
