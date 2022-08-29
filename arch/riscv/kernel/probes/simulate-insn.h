/* SPDX-License-Identifier: GPL-2.0+ */

#ifndef _RISCV_KERNEL_PROBES_SIMULATE_INSN_H
#define _RISCV_KERNEL_PROBES_SIMULATE_INSN_H

#define __RISCV_INSN_FUNCS(name, mask, val)				\
static __always_inline bool riscv_insn_is_##name(probe_opcode_t code)	\
{									\
	BUILD_BUG_ON(~(mask) & (val));					\
	return (code & (mask)) == (val);				\
}									\
bool simulate_##name(u32 opcode, unsigned long addr,			\
		     struct pt_regs *regs)

#define RISCV_INSN_REJECTED(name, code)					\
	do {								\
		if (riscv_insn_is_##name(code)) {			\
			return INSN_REJECTED;				\
		}							\
	} while (0)

__RISCV_INSN_FUNCS(system,	0x7f, 0x73);
__RISCV_INSN_FUNCS(fence,	0x7f, 0x0f);

#define RISCV_INSN_SET_SIMULATE(name, code)				\
	do {								\
		if (riscv_insn_is_##name(code)) {			\
			api->handler = simulate_##name;			\
			return INSN_GOOD_NO_SLOT;			\
		}							\
	} while (0)

__RISCV_INSN_FUNCS(c_j,		0xe003, 0xa001);
__RISCV_INSN_FUNCS(c_jr,	0xf007, 0x8002);
__RISCV_INSN_FUNCS(c_jal,	0xe003, 0x2001);
__RISCV_INSN_FUNCS(c_jalr,	0xf007, 0x9002);
__RISCV_INSN_FUNCS(c_beqz,	0xe003, 0xc001);
__RISCV_INSN_FUNCS(c_bnez,	0xe003, 0xe001);
__RISCV_INSN_FUNCS(c_ebreak,	0xffff, 0x9002);

__RISCV_INSN_FUNCS(auipc,	0x7f, 0x17);
__RISCV_INSN_FUNCS(branch,	0x7f, 0x63);

__RISCV_INSN_FUNCS(jal,		0x7f, 0x6f);
__RISCV_INSN_FUNCS(jalr,	0x707f, 0x67);

/* 0111011 && 0110011 */
__RISCV_INSN_FUNCS(arith_rr, 0x77, 0x33);
/* 0011011 && 0010011 */
__RISCV_INSN_FUNCS(arith_ri, 0x77, 0x13);
__RISCV_INSN_FUNCS(lui, 0x7f, 0x37);
__RISCV_INSN_FUNCS(load, 0x7f, 0x03);
__RISCV_INSN_FUNCS(store, 0x7f, 0x23);
__RISCV_INSN_FUNCS(amo, 0x7f, 0x2f);

#define branch_imm(opcode) \
	(((((opcode) >>  8) & 0xf) <<  1) | \
	 ((((opcode) >> 25) & 0x3f) << 5) | \
	 ((((opcode) >>  7) & 0x1) << 11) | \
	 ((((opcode) >> 31) & 0x1) << 12))

#define branch_offset(opcode) \
	sign_extend32((branch_imm(opcode)), 12)

#define jal_imm(opcode) \
	(((((opcode) >> 21) & 0x3ff) << 1) | \
	 ((((opcode) >> 20) &  0x1) << 11) | \
	 ((((opcode) >> 31) &  0x1) << 20))
#define jal_offset(opcode) \
	sign_extend32(jal_imm(opcode), 20)

#endif /* _RISCV_KERNEL_PROBES_SIMULATE_INSN_H */
