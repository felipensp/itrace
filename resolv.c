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
#include "resolv.h"
#include "trace.h"

resolv_info r_info;

static int _maps_region(const char *line)
{
	uintptr_t start, end;
	char perms[5], filename[PATH_MAX];
	int offset, dmajor, dminor, inode;
	const size_t n = r_info.num_segments;
	resolv_segment *segments = r_info.segments;

	if (sscanf(line, "%" PRIxPTR "-%" PRIxPTR " %s %x %x:%x %u %s",
		&start, &end, perms, &offset, &dmajor, &dminor, &inode, filename) < 6 ||
		(end - start) == 0) {
		return 1;
	}

	if (segments == NULL || n % 5 == 0) {
		segments = (resolv_segment*) realloc(segments,
			sizeof(resolv_segment) * (n + 5));

		if (segments == NULL) {
			return 0;
		}
	}

	segments[n].saddr = start;
	segments[n].eaddr = end;
	memcpy(segments[n].fname, filename, sizeof(filename));
	memcpy(segments[n].perms, perms, sizeof(perms));

	r_info.num_segments++;
	r_info.segments = segments;

	return 1;
}

static int _map_segments()
{
	char fname[PATH_MAX], *line = NULL;
	FILE *fp;
	size_t size;

	snprintf(fname, sizeof(fname), "/proc/%d/maps", tracee.pid);

	if ((fp = fopen(fname, "r")) == NULL) {
		return 0;
	}

	while (getline(&line, &size, fp) != -1) {
		_maps_region(line);
	}

	fclose(fp);

	return 1;
}

void _show_maps()
{
	int i;

	for (i = 0; i < r_info.num_segments; ++i) {
		printf("%" ADDR_FMT "-%" ADDR_FMT " - %s (%s)\n",
			r_info.segments[i].saddr,
			r_info.segments[i].eaddr,
			r_info.segments[i].fname,
			r_info.segments[i].perms);
	}
}

void resolv_startup()
{
	_map_segments();

	if (tracee.flags & SHOW_MAPS) {
		_show_maps();
	}
}

void resolv_shutdown()
{
	free(r_info.segments);
}

int resolv_is_dynamic(uintptr_t addr)
{
	return 0;
}
