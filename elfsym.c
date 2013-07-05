/*
 * itrace
 *
 * ELF symbols specific routines
 *
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
			sizeof(elfsym_sym) * (e_info.nsyms + 5));

		if (e_info.syms == NULL) {
			iprintf("[!] Failed to realloc symbol!");
			return;
		}
	}

	memcpy(e_info.syms[e_info.nsyms].name, name, strlen(name)+1);
	e_info.syms[e_info.nsyms].rel_addr = addr;

	e_info.nsyms++;
}

static void _read_elf_header(uintptr_t baddr)
{
	Elf32_Ehdr ehdr;

	ptrace_read(tracee.pid, baddr, &ehdr, sizeof(ehdr));

	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		iprintf("[!] Invalid ELF on base address\n");
		return;
	}

	e_info.class = (ehdr.e_ident[EI_CLASS] == 1 ? 32 : 64);
	e_info.baddr = baddr;

	if (e_info.class == 32) {
		e_info.phaddr    = e_info.baddr + ehdr.e_phoff;
		e_info.phnum     = ehdr.e_phnum;
		e_info.pie       = (ehdr.e_type == ET_DYN);
		e_info.phentsize = ehdr.e_phentsize;
	} else {
		Elf64_Ehdr ehdr;

		ptrace_read(tracee.pid, baddr, &ehdr, sizeof(ehdr));

		e_info.phaddr    = e_info.baddr + ehdr.e_phoff;
		e_info.phnum     = ehdr.e_phnum;
		e_info.pie       = (ehdr.e_type == ET_DYN);
		e_info.phentsize = ehdr.e_phentsize;
	}
}

static int _read_elf_rela_symbol(int type, uintptr_t rel_addr, uintptr_t *offset)
{
	if (e_info.class == 32) {
		Elf32_Sym sym;
		size_t r_info;

		switch (type) {
			case DT_REL: {
					Elf32_Rel rel;
					ptrace_read(tracee.pid, rel_addr, &rel, sizeof(rel));
					*offset = adjust_addr(rel.r_offset);
					r_info = ELF32_R_SYM(rel.r_info);
				}
				break;
			case DT_RELA: {
					Elf32_Rela rela;
					ptrace_read(tracee.pid, rel_addr, &rela, sizeof(rela));
					*offset = adjust_addr(rela.r_offset);
					r_info = ELF32_R_SYM(rela.r_info);
				}
				break;
		}

		ptrace_read(tracee.pid, e_info.symtab +	(sizeof(sym) * r_info),
			&sym, sizeof(sym));

		return sym.st_name;
	} else {
		Elf64_Sym sym;
		size_t r_info;

		switch (type) {
			case DT_REL: {
					Elf64_Rel rel;
					ptrace_read(tracee.pid, rel_addr, &rel, sizeof(rel));
					*offset = adjust_addr(rel.r_offset);
					r_info = ELF64_R_SYM(rel.r_info);
				}
				break;
			case DT_RELA: {
					Elf64_Rela rela;
					ptrace_read(tracee.pid, rel_addr, &rela, sizeof(rela));
					*offset = adjust_addr(rela.r_offset);
					r_info = ELF64_R_SYM(rela.r_info);
				}
				break;
		}

		ptrace_read(tracee.pid, e_info.symtab +	(sizeof(sym) * r_info),
			&sym, sizeof(sym));

		return sym.st_name;
	}
}

static int _read_elf_phdr_entry(uintptr_t addr, uintptr_t *vaddr, long *memsz)
{
	if (e_info.class == 32) {
		Elf32_Phdr phdr;

		ptrace_read(tracee.pid, addr, &phdr, sizeof(phdr));
		*vaddr = adjust_addr(phdr.p_vaddr);
		*memsz = phdr.p_memsz;

		return phdr.p_type;
	} else {
		Elf64_Phdr phdr;

		ptrace_read(tracee.pid, addr, &phdr, sizeof(phdr));
		*vaddr = adjust_addr(phdr.p_vaddr);
		*memsz = phdr.p_memsz;

		return phdr.p_type;
	}
}

static int _read_elf_dyn_entry(uintptr_t addr, uintptr_t *d_ptr, long *d_val)
{
	if (e_info.class == 32) {
		Elf32_Dyn dyn;

		ptrace_read(tracee.pid, addr, &dyn, sizeof(dyn));

		*d_ptr = adjust_addr(dyn.d_un.d_ptr);
		*d_val = dyn.d_un.d_val;

		return dyn.d_tag;
	} else {
		Elf64_Dyn dyn;

		ptrace_read(tracee.pid, addr, &dyn, sizeof(dyn));

		*d_ptr = adjust_addr(dyn.d_un.d_ptr);
		*d_val = dyn.d_un.d_val;

		return dyn.d_tag;
	}
}

static void _find_rel_symbols(int rel_type, uintptr_t rel_addr, uintptr_t mem_size,
	size_t rel_ent_size)
{
	int i;

	for (i = 0; i < mem_size / rel_ent_size; ++i) {
		char name[MAX_SYM_NAME+1];
		uintptr_t addr;
		uintptr_t symname = _read_elf_rela_symbol(rel_type, rel_addr, &addr);

		memset(name, 0, sizeof(name));
		ptrace_read(tracee.pid, e_info.strtab + symname, name, sizeof(name));
		name[MAX_SYM_NAME] = 0;

		if (name[0] != '\0') {
			_add_symbol(name, addr);
		}

		rel_addr += rel_ent_size;
	}
}

static void _find_dynamic()
{
	uintptr_t addr = e_info.phaddr;
	uintptr_t rel_dyn_addr, rel_plt_addr;
	long mem_size;
	int ptype, i, rel_type;
	size_t dyn_size = e_info.class == 32 ? sizeof(Elf32_Dyn) : sizeof(Elf64_Dyn);
	size_t rel_ent_size = 0, rel_dyn_size, rel_plt_size;

	for (i = 0; i < e_info.phnum; ++i) {
		uintptr_t vaddr;

		ptype = _read_elf_phdr_entry(addr, &vaddr, &mem_size);

		if (ptype == PT_DYNAMIC) {
			addr = vaddr;
			break;
		}

		addr += e_info.phentsize;
	}

	if (ptype != PT_DYNAMIC) {
		return;
	}

	for (i = 0; i < mem_size / dyn_size; ++i) {
		uintptr_t d_ptr;
		long d_val;
		int d_tag = _read_elf_dyn_entry(addr, &d_ptr, &d_val);

		switch (d_tag) {
			case DT_SYMTAB:
				e_info.symtab = d_ptr;
				break;
			case DT_STRTAB:
				e_info.strtab = d_ptr;
				break;
			/* .rel[a].dyn */
			case DT_REL:
			case DT_RELA:
				rel_dyn_addr = d_ptr;
				break;
			/* .rel[a].plt */
			case DT_JMPREL:
				rel_plt_addr = d_ptr;
				break;
			case DT_RELSZ:
			case DT_RELASZ:
				rel_dyn_size = d_val;
				break;
			case DT_PLTRELSZ:
				rel_plt_size = d_val;
				break;
			case DT_PLTREL:
				rel_type = d_val;
				break;
			case DT_RELAENT:
			case DT_RELENT:
				rel_ent_size = d_val;
				break;
		}

		addr += dyn_size;
	}

	if (e_info.symtab != 0 && e_info.strtab != 0) {
		if (rel_dyn_addr != 0) {
			_find_rel_symbols(rel_type, rel_dyn_addr, rel_dyn_size, rel_ent_size);
		}
		if (rel_plt_addr != 0) {
			_find_rel_symbols(rel_type, rel_plt_addr, rel_plt_size, rel_ent_size);
		}
	}
}

int elfsym_startup(uintptr_t baddr)
{
	_read_elf_header(baddr);
	_find_dynamic();

	return 1;
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
