/*
 * itrace
 *
 * ELF symbols specific routines
 */

#include <stdio.h>
#include <elf.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include "elfsym.h"
#include "trace.h"
#include "ptrace.h"

elfsym_info e_info;

inline static uintptr_t adjust_addr(uintptr_t addr)
{
	return e_info.pie ? e_info.baddr + addr : addr;
}

static void _add_symbol(const char *name, uintptr_t addr)
{
	if (e_info.syms == NULL || e_info.nsyms % 5 == 0) {
		e_info.syms = realloc(e_info.syms,
			e_info.nsyms + (sizeof(elfsym_sym) * 5));

		if (e_info.syms == NULL) {
			printf("[!] Failed to realloc symbol!");
			return;
		}
	}

	memcpy(e_info.syms[e_info.nsyms].name, name, strlen(name)+1);
	e_info.syms[e_info.nsyms].rel_addr = addr;

	e_info.nsyms++;
}

static void _find_plt_symbols(uintptr_t rel_addr, uintptr_t rel_size)
{
	ElfW(Rela) rela;
	ElfW(Sym) sym;
	int i;

	for (i = 0; i < rel_size / sizeof(rela); ++i) {
		char name[MAX_SYM_NAME+1];

		ptrace_read(tracee.pid, rel_addr, &rela, sizeof(rela));

		ptrace_read(tracee.pid, e_info.symtab +
			(sizeof(sym)* ELF_R(SYM, rela.r_info)), &sym, sizeof(sym));

		ptrace_read(tracee.pid, e_info.strtab + sym.st_name, name, sizeof(name));
		name[MAX_SYM_NAME] = 0;

		_add_symbol(name, adjust_addr(rela.r_offset));

		rel_addr += sizeof(rela);
	}
}

static void _find_dynamic()
{
	ElfW(Phdr) phdr;
	ElfW(Dyn) dyn;
	uintptr_t addr = e_info.baddr + e_info.ehdr.e_phoff;
	uintptr_t rel_addr, rel_size;
	int i;

	for (i = 0; i < e_info.ehdr.e_phnum; ++i) {
		ptrace_read(tracee.pid, addr, &phdr, sizeof(phdr));

		if (phdr.p_type == PT_DYNAMIC) {
			addr = adjust_addr(phdr.p_vaddr);
			break;
		}

		addr += sizeof(phdr);
	}

	if (phdr.p_type != PT_DYNAMIC) {
		return;
	}

	for (i = 0; i < phdr.p_memsz / sizeof(dyn); ++i) {
		ptrace_read(tracee.pid, addr, &dyn, sizeof(dyn));

		switch (dyn.d_tag) {
			case DT_SYMTAB:
				e_info.symtab = adjust_addr(dyn.d_un.d_ptr);
				break;
			case DT_STRTAB:
				e_info.strtab = adjust_addr(dyn.d_un.d_ptr);
				break;
			case DT_JMPREL:
				rel_addr = adjust_addr(dyn.d_un.d_ptr);
				break;
			case DT_PLTRELSZ:
				rel_size = dyn.d_un.d_val;
				break;
		}

		addr += sizeof(dyn);
	}

	if (e_info.symtab != 0 && e_info.strtab != 0) {
		_find_plt_symbols(rel_addr, rel_size);
	}
}

void elfsym_startup(uintptr_t baddr)
{
	e_info.baddr = baddr;

	ptrace_read(tracee.pid, baddr, &e_info.ehdr, sizeof(ElfW(Ehdr)));

	e_info.pie = e_info.ehdr.e_type == ET_DYN;

	_find_dynamic();
}

void elfsym_shutdown()
{
	free(e_info.syms);
}

const elfsym_sym* elfsym_resolv(uintptr_t addr)
{
	int i;

	for (i = 0; i < e_info.nsyms; ++i) {
		if (e_info.syms[i].rel_addr == addr) {
			return e_info.syms + i;
		}
	}

	return NULL;
}
