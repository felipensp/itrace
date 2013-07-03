/*
 * itrace
 *
 * Disassemble specific routines header
 *
 */

#ifndef ITRACE_DISAS_H
#define ITRACE_DISAS_H

#include <sys/types.h>
#include <sys/user.h>

/*
 * Helper macro to handle user_regs_struct's field names
 * based on the architecture
 */
#if defined(__x86_64__)
# define ADDR_FMT "016lx"
# define reg_eip rip
# define reg_eax rax
# define reg_ebx rbx
# define reg_ecx rcx
# define reg_edx rdx
# define reg_edi rdi
# define reg_esi rsi
# define reg_esp rsp
# define reg_ebp rbp
#else
# define ADDR_FMT "08x"
# define reg_eip eip
# define reg_eax eax
# define reg_ebx ebx
# define reg_ecx ecx
# define reg_edx edx
# define reg_edi edi
# define reg_esi esi
# define reg_esp esp
# define reg_ebp ebp
#endif

void disas_instr(const struct user_regs_struct*);

#endif /* ITRACE_DISAS_H */
