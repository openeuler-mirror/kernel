/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * Format of an instruction in memory.
 *
 * Copyright (C) 2020 Loongson Technology Corporation Limited
 */
#ifndef _UAPI_ASM_INST_H
#define _UAPI_ASM_INST_H

#include <asm/bitfield.h>

enum reg0_op {
	tlbclr_op = 0x19208, gtlbclr_op=0x19208,
	tlbflush_op = 0x19209, gtlbflush_op=0x19209,
	tlbsrch_op = 0x1920a, gtlbsrch_op=0x1920a,
	tlbrd_op = 0x1920b, gtlbrd_op=0x1920b,
	tlbwr_op = 0x1920c, gtlbwr_op=0x1920c,
	tlbfill_op = 0x1920d, gtlbfill_op=0x1920d,
	ertn_op = 0x1920e,
};

enum reg0i15_op {
	break_op = 0x54, dbcl_op, syscall_op, hypcall_op,
	idle_op = 0xc91, dbar_op = 0x70e4, ibar_op,
};

enum reg0i26_op {
	b_op = 0x14, bl_op,
};

enum reg1i20_op {
	lu12iw_op = 0xa, lu32id_op, pcaddi_op, pcalau12i_op,
	pcaddu12i_op, pcaddu18i_op,
};

enum reg1i21_op {
	beqz_op = 0x10, bnez_op, bceqz_op, bcnez_op=0x12, jiscr0_op=0x12, jiscr1_op=0x12,
};

enum reg2_op {
	gr2scr_op = 0x2, scr2gr_op, clow_op,
	clzw_op, ctow_op, ctzw_op, clod_op,
	clzd_op, ctod_op, ctzd_op, revb2h_op,
	revb4h_op, revb2w_op, revbd_op, revh2w_op,
	revhd_op, bitrev4b_op, bitrev8b_op, bitrevw_op,
	bitrevd_op, extwh_op, extwb_op, rdtimelw_op,
	rdtimehw_op, rdtimed_op, cpucfg_op,
	iocsrrdb_op = 0x19200, iocsrrdh_op, iocsrrdw_op, iocsrrdd_op,
	iocsrwrb_op, iocsrwrh_op, iocsrwrw_op, iocsrwrd_op,
	movgr2fcsr_op = 0x4530, movfcsr2gr_op = 0x4532,
	movgr2cf_op = 0x4536, movcf2gr_op = 0x4537,
};

enum reg2ui3_op {
	rotrib_op = 0x261, rcrib_op = 0x281,
};

enum reg2ui4_op {
	rotrih_op = 0x131, rcrih_op = 0x141,
};

enum reg2ui5_op {
	slliw_op = 0x81, srliw_op = 0x89, sraiw_op = 0x91, rotriw_op = 0x99,
	rcriw_op = 0xa1,
};

enum reg2ui6_op {
	sllid_op = 0x41, srlid_op = 0x45, sraid_op = 0x49, rotrid_op = 0x4d,
	rcrid_op = 0x51,
};

enum reg2ui12_op {
	andi_op = 0xd, ori_op, xori_op,
};

enum reg2lsbw_op {
	bstrinsw_op = 0x3, bstrpickw_op = 0x3,
};

enum reg2lsbd_op {
	bstrinsd_op = 0x2, bstrpickd_op = 0x3,
};

enum reg2i8_op {
	lddir_op = 0x190, ldpte_op,
};

enum reg2i8idx1_op {
	vstelmd_op = 0x622,
};

enum reg2i8idx2_op {
	vstelmw_op = 0x312, xvstelmd_op = 0x331,
};

enum reg2i8idx3_op {
	vstelmh_op = 0x18a, xvstelmw_op = 0x199,
};

enum reg2i8idx4_op {
	vstelmb_op = 0xc6, xvstelmh_op = 0xcd,
};

enum reg2i8idx5_op {
	xvstelmb_op = 0x67,
};

enum reg2i9_op {
	vldrepld_op = 0x602, xvldrepld_op = 0x642,
};

enum reg2i10_op {
	vldreplw_op = 0x302, xvldreplw_op = 0x322,
};

enum reg2i11_op {
	vldreplh_op = 0x182, xvldreplh_op = 0x192,
};

enum reg2i12_op {
	slti_op = 0x8, sltui_op, addiw_op, addid_op,
	lu52id_op, cacop_op = 0x18, xvldreplb_op = 0xca,
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
	addu16id_op = 0x4, jirl_op = 0x13, beq_op = 0x16, bne_op, blt_op, bge_op, bltu_op, bgeu_op,
};

enum reg2csr_op {
	csrrd_op = 0x4, csrwr_op = 0x4, csrxchg_op = 0x4,
	gcsrrd_op = 0x5, gcsrwr_op = 0x5, gcsrxchg_op = 0x5,
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

enum reg3sa2_op {
	alslw_op = 0x2, alslwu_op, bytepickw_op, alsld_op = 0x16,

};

enum reg3sa3_op {
	bytepickd_op = 0x3,
};

struct reg2_format {
	__BITFIELD_FIELD(unsigned int opcode : 22,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))
};

struct reg2ui3_format {
	__BITFIELD_FIELD(unsigned int opcode : 19,
	__BITFIELD_FIELD(unsigned int simmediate : 3,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2ui4_format {
	__BITFIELD_FIELD(unsigned int opcode : 18,
	__BITFIELD_FIELD(unsigned int simmediate : 4,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2ui5_format {
	__BITFIELD_FIELD(unsigned int opcode : 17,
	__BITFIELD_FIELD(unsigned int simmediate : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2ui6_format {
	__BITFIELD_FIELD(unsigned int opcode : 16,
	__BITFIELD_FIELD(unsigned int simmediate : 6,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2lsbw_format {
	__BITFIELD_FIELD(unsigned int opcode : 11,
	__BITFIELD_FIELD(unsigned int msbw : 5,
	__BITFIELD_FIELD(unsigned int op : 1,
	__BITFIELD_FIELD(unsigned int lsbw : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))))
};

struct reg2lsbd_format {
	__BITFIELD_FIELD(unsigned int opcode : 10,
	__BITFIELD_FIELD(unsigned int msbd : 6,
	__BITFIELD_FIELD(unsigned int lsbd : 6,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg3_format {
	__BITFIELD_FIELD(unsigned int opcode : 17,
	__BITFIELD_FIELD(unsigned int rk : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg3sa2_format {
	__BITFIELD_FIELD(unsigned int opcode : 15,
	__BITFIELD_FIELD(unsigned int simmediate : 2,
	__BITFIELD_FIELD(unsigned int rk : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg3sa3_format {
	__BITFIELD_FIELD(unsigned int opcode : 14,
	__BITFIELD_FIELD(unsigned int simmediate : 3,
	__BITFIELD_FIELD(unsigned int rk : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg3sa4_format {
	__BITFIELD_FIELD(unsigned int opcode : 13,
	__BITFIELD_FIELD(unsigned int simmediate : 4,
	__BITFIELD_FIELD(unsigned int rk : 5,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg4_format {
	__BITFIELD_FIELD(unsigned int opcode : 12,
	__BITFIELD_FIELD(unsigned int fa : 5,
	__BITFIELD_FIELD(unsigned int fk : 5,
	__BITFIELD_FIELD(unsigned int fj : 5,
	__BITFIELD_FIELD(unsigned int fd : 5,
	;)))))
};

struct reg2i8_format {
	__BITFIELD_FIELD(unsigned int opcode : 14,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i8idx1_format {
	__BITFIELD_FIELD(unsigned int opcode : 13,
	__BITFIELD_FIELD(unsigned int idx : 1,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg2i8idx2_format {
	__BITFIELD_FIELD(unsigned int opcode : 12,
	__BITFIELD_FIELD(unsigned int idx : 2,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg2i8idx3_format {
	__BITFIELD_FIELD(unsigned int opcode : 11,
	__BITFIELD_FIELD(unsigned int idx : 3,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg2i8idx4_format {
	__BITFIELD_FIELD(unsigned int opcode : 10,
	__BITFIELD_FIELD(unsigned int idx : 4,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg2i8idx5_format {
	__BITFIELD_FIELD(unsigned int opcode : 9,
	__BITFIELD_FIELD(unsigned int idx : 5,
	__BITFIELD_FIELD(unsigned int simmediate : 8,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))))
};

struct reg2i9_format {
	__BITFIELD_FIELD(unsigned int opcode : 13,
	__BITFIELD_FIELD(unsigned int simmediate : 9,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i10_format {
	__BITFIELD_FIELD(unsigned int opcode : 12,
	__BITFIELD_FIELD(unsigned int simmediate : 10,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i11_format {
	__BITFIELD_FIELD(unsigned int opcode : 11,
	__BITFIELD_FIELD(unsigned int simmediate : 11,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i12_format {
	__BITFIELD_FIELD(unsigned int opcode : 10,
	__BITFIELD_FIELD(signed int simmediate : 12,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2ui12_format {
	__BITFIELD_FIELD(unsigned int opcode : 10,
	__BITFIELD_FIELD(unsigned int simmediate : 12,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i14_format {
	__BITFIELD_FIELD(unsigned int opcode : 8,
	__BITFIELD_FIELD(unsigned int simmediate : 14,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2i16_format {
	__BITFIELD_FIELD(unsigned int opcode : 6,
	__BITFIELD_FIELD(unsigned int simmediate : 16,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg2csr_format {
	__BITFIELD_FIELD(unsigned int opcode : 8,
	__BITFIELD_FIELD(unsigned int csr : 14,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;))))
};

struct reg1i21_format {
	__BITFIELD_FIELD(unsigned int opcode : 6,
	__BITFIELD_FIELD(unsigned int simmediate_l : 16,
	__BITFIELD_FIELD(unsigned int rj : 5,
	__BITFIELD_FIELD(unsigned int simmediate_h  : 5,
	;))))
};

struct reg1i20_format {
	__BITFIELD_FIELD(unsigned int opcode : 7,
	__BITFIELD_FIELD(unsigned int simmediate : 20,
	__BITFIELD_FIELD(unsigned int rd : 5,
	;)))
};

struct reg0i15_format {
	__BITFIELD_FIELD(unsigned int opcode : 17,
	__BITFIELD_FIELD(unsigned int simmediate : 15,
	;))
};

struct reg0i26_format {
	__BITFIELD_FIELD(unsigned int opcode : 6,
	__BITFIELD_FIELD(unsigned int simmediate_l : 16,
	__BITFIELD_FIELD(unsigned int simmediate_h : 10,
	;)))
};

union loongarch_instruction {
	unsigned int word;
	unsigned short halfword[2];
	unsigned char byte[4];
	struct reg2_format reg2_format;
	struct reg2ui3_format reg2ui3_format;
	struct reg2ui4_format reg2ui4_format;
	struct reg2ui5_format reg2ui5_format;
	struct reg2ui6_format reg2ui6_format;
	struct reg2ui12_format reg2ui12_format;
	struct reg2lsbw_format reg2lsbw_format;
	struct reg2lsbd_format reg2lsbd_format;
	struct reg3_format reg3_format;
	struct reg3sa2_format reg3sa2_format;
	struct reg3sa3_format reg3sa3_format;
	struct reg3sa4_format reg3sa4_format;
	struct reg4_format reg4_format;
	struct reg2i8_format reg2i8_format;
	struct reg2i8idx1_format reg2i8idx1_format;
	struct reg2i8idx2_format reg2i8idx2_format;
	struct reg2i8idx3_format reg2i8idx3_format;
	struct reg2i8idx4_format reg2i8idx4_format;
	struct reg2i8idx5_format reg2i8idx5_format;
	struct reg2i9_format reg2i9_format;
	struct reg2i10_format reg2i10_format;
	struct reg2i11_format reg2i11_format;
	struct reg2i12_format reg2i12_format;
	struct reg2i14_format reg2i14_format;
	struct reg2i16_format reg2i16_format;
	struct reg2csr_format reg2csr_format;
	struct reg1i21_format reg1i21_format;
	struct reg1i20_format reg1i20_format;
	struct reg0i15_format reg0i15_format;
	struct reg0i26_format reg0i26_format;
};

#endif /* _UAPI_ASM_INST_H */
