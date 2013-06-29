/*
 * itrace
 *
 * Address resolver specific routines header
 *
 */

#ifndef ITRACE_RESOLV_H
#define ITRACE_RESOLV_H

#include <limits.h>
#include <stdint.h>

void resolv_startup();
void resolv_shutdown();
int resolv_is_dynamic(uintptr_t);

typedef struct {
	uintptr_t saddr;      /* start address */
	uintptr_t eaddr;      /* end address   */
	char fname[PATH_MAX]; /* file name     */
	char perms[5];        /* permissions   */
} resolv_segment;

typedef struct {
	resolv_segment *segments;
	unsigned int num_segments;
} resolv_info;

extern resolv_info r_info;

#endif /* ITRACE_RESOLV_H */
