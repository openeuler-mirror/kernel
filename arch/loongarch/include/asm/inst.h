/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#ifndef _ASM_INST_H
#define _ASM_INST_H

#include <linux/types.h>
#include <asm/asm.h>

#define INSN_NOP		0x03400000

#define ADDR_IMMMASK_LU52ID	0xFFF0000000000000
#define ADDR_IMMMASK_LU32ID	0x000FFFFF00000000
#define ADDR_IMMMASK_ADDU16ID	0x00000000FFFF0000

#define ADDR_IMMSHIFT_LU52ID	52
#define ADDR_IMMSHIFT_LU32ID	32
#define ADDR_IMMSHIFT_ADDU16ID	16

#define ADDR_IMM(addr, INSN)	((addr & ADDR_IMMMASK_##INSN) >> ADDR_IMMSHIFT_##INSN)

enum reg0i26_op {
	b_op		= 0x14,
	bl_op		= 0x15,
};

enum reg1i20_op {
	lu12iw_op	= 0x0a,
	lu32id_op	= 0x0b,
	pcaddi_op	= 0x0c,
	pcalau12i_op	= 0x0d,
	pcaddu12i_op	= 0x0e,
	pcaddu18i_op	= 0x0f,
};

enum reg1i21_op {
	beqz_op		= 0x10,
	bnez_op		= 0x11,
	bceqz_op	= 0x12, /* bits[9:8] = 0x00 */
	bcnez_op	= 0x12, /* bits[9:8] = 0x01 */
};

enum reg2i12_op {
	slti_op = 0x8, sltui_op, addiw_op, addid_op,
	lu52id_op, cache_op = 0x18, xvldreplb_op = 0xca,
	ldb_op = 0xa0, ldh_op, ldw_op, ldd_op, stb_op, sth_op,
	stw_op, std_op, ldbu_op, ldhu_op, ldwu_op, preld_op,
	flds_op, fsts_op, fldd_op, fstd_op, vld_op, vst_op, xvld_op,
	xvst_op, ldlw_op = 0xb8, ldrw_op, ldld_op, ldrd_op, stlw_op,
	strw_op, stld_op, strd_op, vldreplb_op = 0xc2,
};

enum reg2i14_op {
	llw_op = 0x20, scw_op, lld_op, scd_op, ldptrw_op, stptrw_op,
	ldptrd_op, stptrd_op,
};

enum reg2i16_op {
	jirl_op		= 0x13,
	beq_op		= 0x16,
	bne_op		= 0x17,
	blt_op		= 0x18,
	bge_op		= 0x19,
	bltu_op		= 0x1a,
	bgeu_op		= 0x1b,
};

enum reg3_op {
	asrtled_op = 0x2, asrtgtd_op,
	addw_op = 0x20, addd_op, subw_op, subd_op,
	slt_op, sltu_op, maskeqz_op, masknez_op,
	nor_op, and_op, or_op, xor_op, orn_op,
	andn_op, sllw_op, srlw_op, sraw_op, slld_op,
	srld_op, srad_op, rotrb_op, rotrh_op,
	rotrw_op, rotrd_op, mulw_op, mulhw_op,
	mulhwu_op, muld_op, mulhd_op, mulhdu_op,
	mulwdw_op, mulwdwu_op, divw_op, modw_op,
	divwu_op, modwu_op, divd_op, modd_op,
	divdu_op, moddu_op, crcwbw_op,
	crcwhw_op, crcwww_op, crcwdw_op, crccwbw_op,
	crccwhw_op, crccwww_op, crccwdw_op, addu12iw_op,
	addu12id_op,
	adcb_op = 0x60, adch_op, adcw_op, adcd_op,
	sbcb_op, sbch_op, sbcw_op, sbcd_op,
	rcrb_op, rcrh_op, rcrw_op, rcrd_op,
	ldxb_op = 0x7000, ldxh_op = 0x7008, ldxw_op = 0x7010, ldxd_op = 0x7018,
	stxb_op = 0x7020, stxh_op = 0x7028, stxw_op = 0x7030, stxd_op = 0x7038,
	ldxbu_op = 0x7040, ldxhu_op = 0x7048, ldxwu_op = 0x7050,
	preldx_op = 0x7058, fldxs_op = 0x7060, fldxd_op = 0x7068,
	fstxs_op = 0x7070, fstxd_op = 0x7078, vldx_op = 0x7080,
	vstx_op = 0x7088, xvldx_op = 0x7090, xvstx_op = 0x7098,
	amswapw_op = 0x70c0, amswapd_op, amaddw_op, amaddd_op, amandw_op,
	amandd_op, amorw_op, amord_op, amxorw_op, amxord_op, ammaxw_op,
	ammaxd_op, amminw_op, ammind_op, ammaxwu_op, ammaxdu_op,
	amminwu_op, ammindu_op, amswap_dbw_op, amswap_dbd_op, amadd_dbw_op,
	amadd_dbd_op, amand_dbw_op, amand_dbd_op, amor_dbw_op, amor_dbd_op,
	amxor_dbw_op, amxor_dbd_op, ammax_dbw_op, ammax_dbd_op, ammin_dbw_op,
	ammin_dbd_op, ammax_dbwu_op, ammax_dbdu_op, ammin_dbwu_op,
	ammin_dbdu_op, fldgts_op = 0x70e8, fldgtd_op,
	fldles_op, fldled_op, fstgts_op, fstgtd_op, fstles_op, fstled_op,
	ldgtb_op, ldgth_op, ldgtw_op, ldgtd_op, ldleb_op, ldleh_op, ldlew_op,
	ldled_op, stgtb_op, stgth_op, stgtw_op, stgtd_op, stleb_op, stleh_op,
	stlew_op, stled_op,
};

enum reg2_op {
	iocsrrdb_op = 0x19200, iocsrrdh_op, iocsrrdw_op, iocsrrdd_op,
	iocsrwrb_op, iocsrwrh_op, iocsrwrw_op, iocsrwrd_op,
};

struct reg0i26_format {
	unsigned int immediate_h : 10;
	unsigned int immediate_l : 16;
	unsigned int opcode : 6;
};

struct reg1i20_format {
	unsigned int rd : 5;
	unsigned int immediate : 20;
	unsigned int opcode : 7;
};

struct reg1i21_format {
	unsigned int immediate_h  : 5;
	unsigned int rj : 5;
	unsigned int immediate_l : 16;
	unsigned int opcode : 6;
};

struct reg2_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int opcode : 22;
};

struct reg2i12_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 12;
	unsigned int opcode : 10;
};

struct reg2i14_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int simmediate : 14;
	unsigned int opcode : 8;
};

struct reg0i15_format {
	unsigned int simmediate	: 15;
	unsigned int opcode	: 17;
};

struct reg2i16_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int immediate : 16;
	unsigned int opcode : 6;
};

struct reg3_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int rk : 5;
	unsigned int opcode : 17;
};

struct reg2csr_format {
	unsigned int rd : 5;
	unsigned int rj : 5;
	unsigned int csr : 14;
	unsigned int opcode : 8;
};

union loongarch_instruction {
	unsigned int word;
	struct reg0i26_format reg0i26_format;
	struct reg1i20_format reg1i20_format;
	struct reg1i21_format reg1i21_format;
	struct reg3_format reg3_format;
	struct reg2_format reg2_format;
	struct reg2i12_format reg2i12_format;
	struct reg2i14_format reg2i14_format;
	struct reg2i16_format reg2i16_format;
	struct reg2csr_format	reg2csr_format;
	struct reg0i15_format	reg0i15_format;
};

#define LOONGARCH_INSN_SIZE	sizeof(union loongarch_instruction)

enum loongarch_gpr {
	LOONGARCH_GPR_ZERO = 0,
	LOONGARCH_GPR_RA = 1,
	LOONGARCH_GPR_TP = 2,
	LOONGARCH_GPR_SP = 3,
	LOONGARCH_GPR_A0 = 4,	/* Reused as V0 for return value */
	LOONGARCH_GPR_A1,	/* Reused as V1 for return value */
	LOONGARCH_GPR_A2,
	LOONGARCH_GPR_A3,
	LOONGARCH_GPR_A4,
	LOONGARCH_GPR_A5,
	LOONGARCH_GPR_A6,
	LOONGARCH_GPR_A7,
	LOONGARCH_GPR_T0 = 12,
	LOONGARCH_GPR_T1,
	LOONGARCH_GPR_T2,
	LOONGARCH_GPR_T3,
	LOONGARCH_GPR_T4,
	LOONGARCH_GPR_T5,
	LOONGARCH_GPR_T6,
	LOONGARCH_GPR_T7,
	LOONGARCH_GPR_T8,
	LOONGARCH_GPR_FP = 22,
	LOONGARCH_GPR_S0 = 23,
	LOONGARCH_GPR_S1,
	LOONGARCH_GPR_S2,
	LOONGARCH_GPR_S3,
	LOONGARCH_GPR_S4,
	LOONGARCH_GPR_S5,
	LOONGARCH_GPR_S6,
	LOONGARCH_GPR_S7,
	LOONGARCH_GPR_S8,
	LOONGARCH_GPR_MAX
};

#define is_imm12_negative(val)	is_imm_negative(val, 12)

static inline bool is_imm_negative(unsigned long val, unsigned int bit)
{
	return val & (1UL << (bit - 1));
}

static inline unsigned long sign_extend(unsigned long val, unsigned int idx)
{
	if (!is_imm_negative(val, idx + 1))
		return ((1UL << idx) - 1) & val;
	else
		return ~((1UL << idx) - 1) | val;
}

static inline bool is_pc_ins(union loongarch_instruction *ip)
{
	return ip->reg1i20_format.opcode >= pcaddi_op &&
			ip->reg1i20_format.opcode <= pcaddu18i_op;
}

static inline bool is_branch_ins(union loongarch_instruction *ip)
{
	return ip->reg1i21_format.opcode >= beqz_op &&
		ip->reg1i21_format.opcode <= bgeu_op;
}

static inline bool is_ra_save_ins(union loongarch_instruction *ip)
{
	/* st.d $ra, $sp, offset */
	return ip->reg2i12_format.opcode == std_op &&
		ip->reg2i12_format.rj == LOONGARCH_GPR_SP &&
		ip->reg2i12_format.rd == LOONGARCH_GPR_RA &&
		!is_imm12_negative(ip->reg2i12_format.immediate);
}

static inline bool is_stack_alloc_ins(union loongarch_instruction *ip)
{
	/* addi.d $sp, $sp, -imm */
	return ip->reg2i12_format.opcode == addid_op &&
		ip->reg2i12_format.rj == LOONGARCH_GPR_SP &&
		ip->reg2i12_format.rd == LOONGARCH_GPR_SP &&
		is_imm12_negative(ip->reg2i12_format.immediate);
}

u32 larch_insn_gen_lu32id(enum loongarch_gpr rd, int imm);
u32 larch_insn_gen_lu52id(enum loongarch_gpr rd, enum loongarch_gpr rj, int imm);
u32 larch_insn_gen_jirl(enum loongarch_gpr rd, enum loongarch_gpr rj, unsigned long pc, unsigned long dest);

#endif /* _ASM_INST_H */
