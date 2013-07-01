/*
 * itrace
 *
 * ELF symbols specific routines header
 *
 */

#ifndef ITRACE_ELFSYM_H
#define ITRACE_ELFSYM_H

#include <elf.h>
#include <link.h>

#define MAX_SYM_NAME 50

#define ELF_R(x,y) _ELF_R(ELF, __ELF_NATIVE_CLASS, x, y)
#define _ELF_R(x,y,z,w) __ELF_R(x, y, z, w)
#define __ELF_R(x,y,z,w) x##y##_R_##z(w)

typedef struct {
	char name[MAX_SYM_NAME]; /* Symbol name     */
	uintptr_t rel_addr;      /* Relocation addr */
} elfsym_sym;

typedef struct {
	ElfW(Ehdr) ehdr;     /* ELF header                        */
	int pie;             /* Indicates if the program is a PIE */
	uintptr_t baddr;     /* Executable base addres            */
	uintptr_t symtab;    /* Dynamic symbol table              */
	uintptr_t strtab;    /* Dynamic string table              */
	unsigned int nsyms;  /* Number of symbols                 */
	elfsym_sym *syms;    /* Symbols                           */
} elfsym_info;

void elfsym_startup(uintptr_t);
void elfsym_shutdown();
const elfsym_sym* elfsym_resolv();

extern elfsym_info e_info;

#endif /* ITRACE_ELFSYM_H */
