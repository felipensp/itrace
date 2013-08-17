/*
 * itrace
 *
 * Address resolver specific routines
 *
 */

#include <stdio.h>
#include <limits.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "resolv.h"
#include "trace.h"
#include "ptrace.h"
#include "elfsym.h"
#include "disas.h"

resolv_info r_info;

static int _map_region(const char *prog, const char *line)
{
	uintptr_t start, end;
	char perms[5], fname[PATH_MAX] = {0};
	int offset, dmajor, dminor, inode;
	const size_t n = r_info.num_segments;
	resolv_segment *segments = r_info.segments;

	if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %s %x %x:%x %u %s",
		&start, &end, perms, &offset, &dmajor, &dminor, &inode, fname) < 6 ||
		(end - start) == 0) {
		return 0;
	}

	if (segments == NULL || n % 5 == 0) {
		segments = realloc(segments, sizeof(resolv_segment) * (n + 5));

		if (segments == NULL) {
			return 0;
		}
	}

	segments[n].saddr = start;
	segments[n].eaddr = end;
	segments[n].is_dynamic = 1;

	if (memcmp(fname, prog, strlen(prog)+1) == 0) {
		if (r_info.baddr == 0) {
			r_info.baddr = start;
		}
		segments[n].is_dynamic = 0;
	}

	memcpy(segments[n].fname, fname, sizeof(fname));
	memcpy(segments[n].perms, perms, sizeof(perms));

	r_info.num_segments++;
	r_info.segments = segments;

	return 1;
}

static int _map_segments()
{
	char fname[PATH_MAX], lname[PATH_MAX], *line = NULL;
	FILE *fp;
	size_t size;

	if (r_info.segments) {
		free(r_info.segments);
		r_info.segments = NULL;
		r_info.num_segments = 0;
	}

	if (tracee.prog) {
		if (realpath(tracee.prog, lname) == NULL) {
			return 0;
		}
	} else {
		snprintf(fname, sizeof(fname), "/proc/%d/exe", tracee.pid);
		if (readlink(fname, lname, sizeof(lname)) != -1) {
			return 0;
		}
	}

	snprintf(fname, sizeof(fname), "/proc/%d/maps", tracee.pid);

	if ((fp = fopen(fname, "r")) == NULL) {
		return 0;
	}

	while (getline(&line, &size, fp) != -1) {
		_map_region(lname, line);
	}

	free(line);
	fclose(fp);

	return 1;
}

void resolv_show_maps()
{
	int i;

	iprintf("Maps:\n");
	for (i = 0; i < r_info.num_segments; ++i) {
		iprintf("%" ADDR_FMT "-%" ADDR_FMT " - %s (%s) %d\n",
			r_info.segments[i].saddr,
			r_info.segments[i].eaddr,
			r_info.segments[i].fname,
			r_info.segments[i].perms,
			r_info.segments[i].is_dynamic);
	}
}

void resolv_startup()
{
	if (!_map_segments()) {
		iprintf("[!] Failed to read /proc/%d/maps file!\n", tracee.pid);
		return;
	}

	elfsym_startup(r_info.baddr);
}

void resolv_shutdown()
{
	free(r_info.segments);

	elfsym_shutdown();
}

int resolv_is_dynamic(uintptr_t addr)
{
	int i = 0, try = 0;
	resolv_segment *segs;

find:
	segs = r_info.segments;

	while (i < r_info.num_segments) {
		if (segs[i].saddr <= addr && segs[i].eaddr >= addr) {
			return segs[i].is_dynamic;
		}
		++i;
	}

	if (!try) {
		/*
		 * Remaps the segments when the addr is not found
		 */
		_map_segments();

		try = 1;
		goto find;
	}

	return 0;
}

const char *resolv_symbol(uintptr_t addr)
{
	const elfsym_sym *sym = elfsym_resolv(addr);

	return sym ? sym->name : NULL;
}
