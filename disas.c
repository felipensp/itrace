/*
 * itrace
 *
 * Disassemble specific routines
 *
 */

#include <stdlib.h>
#include <inttypes.h>
#include <libudis86/extern.h>
#include <libudis86/types.h>
#include "disas.h"
#include "elfsym.h"
#include "ptrace.h"
#include "trace.h"
#include "resolv.h"

/*
 * Returns the register name according to the ELF class
 */
static const char *_reg_name(enum ud_type reg)
{
	switch (reg) {
		case UD_R_EAX: return e_info.class == 32 ? "eax" : "rax";
		case UD_R_EBX: return e_info.class == 32 ? "ebx" : "rbx";
		case UD_R_ECX: return e_info.class == 32 ? "ecx" : "rcx";
		case UD_R_EDX: return e_info.class == 32 ? "edx" : "rsx";
		case UD_R_ESI: return e_info.class == 32 ? "esi" : "rsi";
		case UD_R_EDI: return e_info.class == 32 ? "edi" : "rdi";
		case UD_R_ESP: return e_info.class == 32 ? "esp" : "rsp";
		case UD_R_EBP: return e_info.class == 32 ? "ebp" : "rbp";
		case UD_R_RIP: return e_info.class == 32 ? "eip" : "rip";
		default:       return "unknown";
	}
}

/*
 * Returns the value of register
 */
static long _reg_value(enum ud_type type, const struct user_regs_struct *regs)
{
	long val;

	switch (type) {
		case UD_R_EAX: val = regs->reg_eax; break;
		case UD_R_EBX: val = regs->reg_ebx; break;
		case UD_R_ECX: val = regs->reg_ecx; break;
		case UD_R_EDX: val = regs->reg_edx; break;
		case UD_R_ESI: val = regs->reg_esi; break;
		case UD_R_EDI: val = regs->reg_edi; break;
		case UD_R_ESP: val = regs->reg_esp; break;
		case UD_R_EBP: val = regs->reg_ebp; break;
		case UD_R_RIP: val = regs->reg_eip; break;
		default:       val = 0;
	}

	return val;
}

/*
 * Displays the register information according to the ELF class
 */
static void _dump_regs(const struct user_regs_struct *regs)
{
	const char *fmt  = e_info.class == 32 ? "%s=0x%08lx | " : "%s=0x%016lx | ";
	const char *fmt2 = e_info.class == 32 ? "%s=0x%08lx \n" : "%s=0x%016lx \n";

	iprintf(fmt,  _reg_name(UD_R_EAX), regs->reg_eax);
	iprintf(fmt,  _reg_name(UD_R_EBX), regs->reg_ebx);
	iprintf(fmt2, _reg_name(UD_R_ECX), regs->reg_ecx);
	iprintf(fmt,  _reg_name(UD_R_EDX), regs->reg_edx);
	iprintf(fmt,  _reg_name(UD_R_ESI), regs->reg_esi);
	iprintf(fmt2, _reg_name(UD_R_EDI), regs->reg_edi);
	iprintf(fmt,  _reg_name(UD_R_ESP), regs->reg_esp);
	iprintf(fmt,  _reg_name(UD_R_EBP), regs->reg_ebp);
	iprintf(fmt2, _reg_name(UD_R_RIP), regs->reg_eip);
}

/*
 * Displays 4 long from the top of stack
 */
static void _dump_stack(const struct user_regs_struct *regs)
{
	long addr = 0;
	int i;
	size_t lsize = e_info.class == 32 ? 4 : 8;

	iprintf("Stack:\n");
	iprintf(e_info.class == 32 ? "0x%08lx [ " : "0x%016lx [ ", regs->reg_esp);

	for (i = 0; i < 4; ++i) {
		ptrace_read(tracee.pid, regs->reg_esp + (i * lsize), &addr, lsize);

		iprintf(e_info.class == 32 ? "0x%08lx " : "0x%016lx ", addr);
	}

	iprintf(e_info.class == 32 ? "] 0x%08lx\n" : "] 0x%016lx\n", regs->reg_ebp);
}

static long _op_value(const ud_operand_t *op, const struct user_regs_struct *regs)
{
	switch (op->type) {
		case UD_OP_REG:
			return _reg_value(op->base, regs);
		case UD_OP_IMM:
			return op->lval.sdword;
		case UD_OP_MEM:
		case UD_OP_PTR:
		case UD_OP_JIMM:
		case UD_OP_CONST:
		default:
			return 0;
	}
}

/*
 * Provides additional comments to the disassembled instruction
 */
static char *_instr_comments(ud_t *ud_obj, const struct user_regs_struct *regs)
{
	char *comment = NULL;

	switch (ud_obj->mnemonic) {
		case UD_Isyscall:  /* syscall   */
		case UD_Isysenter: /* sysenter  */
		case UD_Iint:      /* int $0x80 */
			if (ud_obj->mnemonic == UD_Iint) {
				const ud_operand_t *op = ud_insn_opr(ud_obj, 0);

				if (op->lval.sdword != 0x80) {
					return NULL;
				}
			}
			comment = malloc(sizeof(char) * 50);
			snprintf(comment, 50, " # syscall number = %ld", regs->reg_eax);
			break;

		case UD_Iret:    /* ret  */
		case UD_Iretf: { /* retf */
				long retaddr = 0;

				comment = malloc(sizeof(char) * 50);
				ptrace_read(tracee.pid, regs->reg_esp, &retaddr,
					(e_info.class == 32 ? 4 : 8));

				snprintf(comment, 50, " # %#lx", retaddr);
			}
			break;

		case UD_Ijmp: { /* jmp */
				const ud_operand_t *op = ud_insn_opr(ud_obj, 0);
				const char *sym = NULL;

				if (e_info.class == 64
					&& op->type == UD_OP_MEM
					&& op->base == UD_R_RIP) {
					/* Possible PLT stub on x86_64 */

					sym = resolv_symbol(
						regs->reg_eip +	op->lval.sdword + ud_insn_len(ud_obj));

				} else if (e_info.class == 32 && op->type == UD_OP_MEM) {
					/* Possible PLT stub on x86 */
					sym = resolv_symbol(op->lval.sdword);

				} else if (op->type == UD_OP_REG) {
					comment = malloc(sizeof(char) * 80);
					snprintf(comment, 80, " # %s = %#lx",
						_reg_name(op->base), _reg_value(op->base, regs));

					return comment;
				}

				if (sym) {
					comment = malloc(sizeof(char) * 80);
					snprintf(comment, 80, " # %s@got", sym);
				}
			}
			break;

		case UD_Ipop:    /* pop  */
		case UD_Iinc:    /* inc  */
		case UD_Idec:    /* dec  */
		case UD_Ipush: { /* push */
				const ud_operand_t *op = ud_insn_opr(ud_obj, 0);

				if (op->type != UD_OP_REG) {
					return NULL;
				}

				if (ud_obj->mnemonic == UD_Ipop) {
					long stack_val = 0;

					ptrace_read(tracee.pid, regs->reg_esp, &stack_val,
						(e_info.class == 32 ? 4 : 8));

					comment = malloc(sizeof(char) * 80);
					snprintf(comment, 80, " # %s = %#lx",
						_reg_name(op->base), stack_val);
				} else {
					long val = _reg_value(op->base, regs);

					if (ud_obj->mnemonic == UD_Iinc) {
						++val;
					} else if (ud_obj->mnemonic == UD_Idec) {
						--val;
					}

					comment = malloc(sizeof(char) * 80);
					snprintf(comment, 80, " # %s = %#lx",
						_reg_name(op->base), val);
				}
			}
			break;

		case UD_Isub:   /* sub */
		case UD_Iadd: { /* add */
				const ud_operand_t *dst = ud_insn_opr(ud_obj, 0);
				const ud_operand_t *src = ud_insn_opr(ud_obj, 1);
				long dst_val, src_val = 0;

				switch (src->type) {
					case UD_OP_REG:
						src_val = _reg_value(src->base, regs);
						break;
					case UD_OP_IMM:
						src_val = src->lval.sdword;
						break;
					default:
						return NULL;
				}
				dst_val = _reg_value(dst->base, regs);

				if (ud_obj->mnemonic == UD_Isub) {
					dst_val -= src_val;
				} else {
					dst_val += src_val;
				}

				comment = malloc(sizeof(char) * 80);
				snprintf(comment, 80, " # %s = %#lx",
					_reg_name(dst->base), dst_val);
			}
			break;

		case UD_Ixor: { /* xor */
				const ud_operand_t *dst = ud_insn_opr(ud_obj, 0);
				long op_val  = _op_value(dst, regs);
				long op2_val = _op_value(ud_insn_opr(ud_obj, 1), regs);

				comment = malloc(sizeof(char) * 80);
				snprintf(comment, 80, " # %s = %#lx",
					_reg_name(dst->base), op_val ^ op2_val);
			}
			break;

		default:
			break;
	}
	return comment;
}

/*
 * Disassemble the instruction pointed by the EIP/RIP register
 */
void disas_instr(const struct user_regs_struct *regs)
{
	unsigned char instrs[16] = {0};
	char *comment = NULL;
	ud_t ud_obj;
	uintptr_t addr = regs->reg_eip;

	/* libudis86 disassembler setup */
	ud_init(&ud_obj);
	ud_set_mode(&ud_obj, e_info.class);
	ud_set_vendor(&ud_obj, UD_VENDOR_AMD);
	ud_set_pc(&ud_obj, regs->reg_eip);
	ud_set_syntax(&ud_obj, tracee.syntax ? UD_SYN_INTEL : UD_SYN_ATT);
	ud_set_input_buffer(&ud_obj, instrs, sizeof(instrs)-1);

	/* Read the instruction (x86-64 may be at most 15 bytes) */
	ptrace_read(tracee.pid, regs->reg_eip, instrs, sizeof(instrs));

	if (tracee.flags & SHOW_REGISTERS) {
		_dump_regs(regs);
	}

	if (tracee.flags & SHOW_STACK) {
		_dump_stack(regs);
	}

	ud_disassemble(&ud_obj);

	if (tracee.flags & SHOW_COMMENTS) {
		comment = _instr_comments(&ud_obj, regs);
	}

	iprintf("%#" PRIxPTR ":\t%-20s\t%-30s%s\n",
		addr,
		ud_insn_hex(&ud_obj),
		ud_insn_asm(&ud_obj),
		comment ? comment : "");

	if (comment) {
		free(comment);
	}
}
