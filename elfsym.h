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

typedef struct {
	char name[MAX_SYM_NAME]; /* Symbol name     */
	uintptr_t rel_addr;      /* Relocation addr */
} elfsym_sym;

typedef struct {
	int class;           /* File's class (1=32 bit or 2=64b)  */
	int pie;             /* Indicates if the program is a PIE */
	uintptr_t baddr;     /* Executable base addres            */
	uintptr_t phaddr;    /* Program header address            */
	uintptr_t symtab;    /* Dynamic symbol table              */
	uintptr_t strtab;    /* Dynamic string table              */
	unsigned int phnum;  /* Number of program headers         */
	unsigned int nsyms;  /* Number of symbols                 */
	elfsym_sym *syms;    /* Symbols                           */
} elfsym_info;

int elfsym_startup(uintptr_t);
void elfsym_shutdown();
const elfsym_sym* elfsym_resolv();

extern elfsym_info e_info;

#endif /* ITRACE_ELFSYM_H */
