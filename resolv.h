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
void resolv_show_maps();
const char* resolv_symbol(uintptr_t);

typedef struct {
	uintptr_t saddr;      /* Start address */
	uintptr_t eaddr;      /* End address   */
	char fname[PATH_MAX]; /* File name     */
	char perms[5];        /* Permissions   */
	int is_dynamic;
} resolv_segment;

typedef struct {
	uintptr_t baddr;            /* Base address of executable     */
	resolv_segment *segments;   /* Segments mapped to the process */
	unsigned int num_segments;  /* Number of segments             */
} resolv_info;

extern resolv_info r_info;

#endif /* ITRACE_RESOLV_H */
