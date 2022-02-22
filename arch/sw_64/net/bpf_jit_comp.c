// SPDX-License-Identifier: GPL-2.0
/*
 * BPF JIT compiler for SW64
 *
 * Copyright (C) Mao Minkai
 * Author: Mao Minkai
 *
 * This file is taken from arch/arm64/net/bpf_jit_comp.c
 *	Copyright (C) 2014-2016 Zi Shen Lim <zlim.lnx@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/printk.h>

#include <asm/cacheflush.h>

#include "bpf_jit.h"

#define TMP_REG_1 (MAX_BPF_JIT_REG + 0)
#define TMP_REG_2 (MAX_BPF_JIT_REG + 1)
#define TCALL_CNT (MAX_BPF_JIT_REG + 2)

/*
 * TO-DO List:
 *	DIV
 *	MOD
 */

static const int bpf2sw64[] = {
	/* return value from in-kernel function, and exit value from eBPF */
	[BPF_REG_0] = SW64_BPF_REG_V0,
	/* arguments from eBPF program to in-kernel function */
	[BPF_REG_1] = SW64_BPF_REG_A1,
	[BPF_REG_2] = SW64_BPF_REG_A2,
	[BPF_REG_3] = SW64_BPF_REG_A3,
	[BPF_REG_4] = SW64_BPF_REG_A4,
	[BPF_REG_5] = SW64_BPF_REG_A5,
	/* callee saved registers that in-kernel function will preserve */
	[BPF_REG_6] = SW64_BPF_REG_S1,
	[BPF_REG_7] = SW64_BPF_REG_S2,
	[BPF_REG_8] = SW64_BPF_REG_S3,
	[BPF_REG_9] = SW64_BPF_REG_S4,
	/* read-only frame pointer to access stack */
	[BPF_REG_FP] = SW64_BPF_REG_S0,
	/* temporary registers for internal BPF JIT */
	[TMP_REG_1] = SW64_BPF_REG_T1,
	[TMP_REG_2] = SW64_BPF_REG_T2,
	/* tail_call_cnt */
	[TCALL_CNT] = SW64_BPF_REG_S5,
	/* temporary register for blinding constants */
	[BPF_REG_AX] = SW64_BPF_REG_T12,
};

struct jit_ctx {
	const struct bpf_prog *prog;
	int idx;		// JITed instruction index
	int epilogue_offset;
	int *insn_offset;	// [bpf_insn_idx] = jited_insn_idx
	u32 *image;		// JITed instruction
	u32 stack_size;
};

struct sw64_jit_data {
	struct bpf_binary_header *header;
	u8 *image;	// bpf instruction
	struct jit_ctx ctx;
};

static inline u32 sw64_bpf_gen_format_br(int opcode, enum sw64_bpf_registers ra, u32 disp)
{
	opcode = opcode << SW64_BPF_OPCODE_OFFSET;
	ra = ra << SW64_BPF_RA_OFFSET;
	return opcode | ra | disp;
}

static inline u32 sw64_bpf_gen_format_ls(int opcode, enum sw64_bpf_registers ra,
		enum sw64_bpf_registers rb, u16 disp)
{
	opcode = opcode << SW64_BPF_OPCODE_OFFSET;
	ra = ra << SW64_BPF_RA_OFFSET;
	rb = rb << SW64_BPF_RB_OFFSET;
	return opcode | ra | rb | disp;
}

static inline u32 sw64_bpf_gen_format_simple_alu_reg(int opcode, enum sw64_bpf_registers ra,
		enum sw64_bpf_registers rb, enum sw64_bpf_registers rc, int function)
{
	opcode = opcode << SW64_BPF_OPCODE_OFFSET;
	ra = ra << SW64_BPF_RA_OFFSET;
	rb = rb << SW64_BPF_RB_OFFSET;
	rc = rc << SW64_BPF_SIMPLE_ALU_RC_OFFSET;
	function = function << SW64_BPF_SIMPLE_ALU_FUNC_OFFSET;
	return opcode | ra | rb | function | rc;
}

static inline u32 sw64_bpf_gen_format_simple_alu_imm(int opcode, enum sw64_bpf_registers ra,
		enum sw64_bpf_registers rc, u8 imm, int function)
{
	opcode = opcode << SW64_BPF_OPCODE_OFFSET;
	ra = ra << SW64_BPF_RA_OFFSET;
	rc = rc << SW64_BPF_SIMPLE_ALU_RC_OFFSET;
	imm = imm << SW64_BPF_SIMPLE_ALU_IMM_OFFSET;
	function = function << SW64_BPF_SIMPLE_ALU_FUNC_OFFSET;
	return opcode | ra | imm | function | rc;
}

static inline void emit(const u32 insn, struct jit_ctx *ctx)
{
	if (ctx->image != NULL)
		ctx->image[ctx->idx] = insn;

	ctx->idx++;
}

static inline void emit_sw64_ldu64(const int dst, const u64 imm64, struct jit_ctx *ctx)
{
	u16 imm_tmp;
	int reg_tmp = SW64_BPF_REG_T8;

	imm_tmp = (imm64 >> 60) & 0xf;
	emit(SW64_BPF_LDI(dst, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(dst, 60, dst), ctx);

	imm_tmp = (imm64 >> 45) & 0x7fff;
	emit(SW64_BPF_LDI(reg_tmp, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(reg_tmp, 45, reg_tmp), ctx);
	emit(SW64_BPF_ADDL_REG(dst, reg_tmp, dst), ctx);

	imm_tmp = (imm64 >> 30) & 0x7fff;
	emit(SW64_BPF_LDI(reg_tmp, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(reg_tmp, 30, reg_tmp), ctx);
	emit(SW64_BPF_ADDL_REG(dst, reg_tmp, dst), ctx);

	imm_tmp = (imm64 >> 15) & 0x7fff;
	emit(SW64_BPF_LDI(reg_tmp, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(reg_tmp, 15, reg_tmp), ctx);
	emit(SW64_BPF_ADDL_REG(dst, reg_tmp, dst), ctx);

	imm_tmp = imm64 & 0x7fff;
	emit(SW64_BPF_LDI(dst, dst, imm_tmp), ctx);
}

static inline void emit_sw64_ldu32(const int dst, const u32 imm32, struct jit_ctx *ctx)
{
	u16 imm_tmp;
	int reg_tmp = SW64_BPF_REG_T8;

	imm_tmp = (imm32 >> 30) & 3;
	emit(SW64_BPF_LDI(dst, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(dst, 30, dst), ctx);

	imm_tmp = (imm32 >> 15) & 0x7fff;
	emit(SW64_BPF_LDI(reg_tmp, SW64_BPF_REG_ZR, imm_tmp), ctx);
	emit(SW64_BPF_SLL_IMM(reg_tmp, 15, reg_tmp), ctx);
	emit(SW64_BPF_ADDL_REG(dst, reg_tmp, dst), ctx);

	imm_tmp = imm32 & 0x7fff;
	emit(SW64_BPF_LDI(dst, dst, imm_tmp), ctx);
}

static inline void emit_sw64_lds32(const int dst, const s32 imm32, struct jit_ctx *ctx)
{
	s16 hi = imm32 >> 16;
	s16 lo = imm32 & 0xffff;
	int reg_tmp = SW64_BPF_REG_T8;

	emit(SW64_BPF_LDIH(dst, SW64_BPF_REG_ZR, hi), ctx);
	if (lo & 0x8000) {	// sign bit is 1
		lo = lo & 0x7fff;
		emit(SW64_BPF_LDI(reg_tmp, SW64_BPF_REG_ZR, 1), ctx);
		emit(SW64_BPF_SLL_IMM(reg_tmp, 15, reg_tmp), ctx);
		emit(SW64_BPF_ADDL_REG(dst, reg_tmp, dst), ctx);
		emit(SW64_BPF_LDI(dst, dst, lo), ctx);
	} else {	// sign bit is 0
		emit(SW64_BPF_LDI(dst, dst, lo), ctx);
	}
}

/* dst = ra / rb */
static void emit_sw64_div(const int ra, const int rb, const int dst, struct jit_ctx *ctx)
{
	pr_err("DIV is not supported for now.\n");
}

/* dst = ra % rb */
static void emit_sw64_mod(const int ra, const int rb, const int dst, struct jit_ctx *ctx)
{
	pr_err("MOD is not supported for now.\n");
}

static void emit_sw64_htobe16(const int dst, struct jit_ctx *ctx)
{
	int tmp = SW64_BPF_REG_T8;

	emit(SW64_BPF_LDI(tmp, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp, 0x2, tmp), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(dst, 0x1, dst), ctx);
	emit(SW64_BPF_SRL_REG(tmp, 8, tmp), ctx);
	emit(SW64_BPF_SLL_REG(dst, 8, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp, dst), ctx);
}

static void emit_sw64_htobe32(const int dst, struct jit_ctx *ctx)
{
	int tmp1 = SW64_BPF_REG_T8;
	int tmp2 = SW64_BPF_REG_T9;

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x1, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x8, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(dst, 0x6, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 24, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 24, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x2, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x4, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(dst, 0x9, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 8, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 8, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);
}

static void emit_sw64_htobe64(const int dst, struct jit_ctx *ctx)
{
	int tmp1 = SW64_BPF_REG_T8;
	int tmp2 = SW64_BPF_REG_T9;

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x1, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x80, tmp1), ctx);
	emit(SW64_BPF_ZAP_IMM(dst, 0x81, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 56, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 56, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x2, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x40, tmp1), ctx);
	emit(SW64_BPF_ZAP_IMM(dst, 0x42, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 40, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 40, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x4, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x20, tmp1), ctx);
	emit(SW64_BPF_ZAP_IMM(dst, 0x24, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 24, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 24, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);

	emit(SW64_BPF_LDI(tmp1, dst, 0), ctx);
	emit(SW64_BPF_LDI(tmp2, dst, 0), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp1, 0x8, tmp1), ctx);
	emit(SW64_BPF_ZAPNOT_IMM(tmp2, 0x10, tmp1), ctx);
	emit(SW64_BPF_ZAP_IMM(dst, 0x18, dst), ctx);
	emit(SW64_BPF_SLL_IMM(tmp1, 8, tmp1), ctx);
	emit(SW64_BPF_SRL_IMM(tmp2, 8, tmp2), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
	emit(SW64_BPF_ADDL_REG(dst, tmp2, dst), ctx);
}

static void jit_fill_hole(void *area, unsigned int size)
{
	memset(area, SW64_BPF_ILLEGAL_INSN, size);
}

static int offset_to_epilogue(const struct jit_ctx *ctx)
{
	return ctx->epilogue_offset - ctx->idx;
}

/* For tail call to jump into */
#define PROLOGUE_OFFSET 8

static void build_prologue(struct jit_ctx *ctx, bool was_classic)
{
	const int r6 = bpf2sw64[BPF_REG_6];
	const int r7 = bpf2sw64[BPF_REG_7];
	const int r8 = bpf2sw64[BPF_REG_8];
	const int r9 = bpf2sw64[BPF_REG_9];
	const int fp = bpf2sw64[BPF_REG_FP];
	const int tcc = bpf2sw64[TCALL_CNT];
	const int tmp1 = bpf2sw64[TMP_REG_1];

	/* Save callee-saved registers */
	emit(SW64_BPF_SUBL_REG(SW64_BPF_REG_SP, 56, SW64_BPF_REG_SP), ctx);
	emit(SW64_BPF_STL(r6, SW64_BPF_REG_SP, 0), ctx);
	emit(SW64_BPF_STL(r7, SW64_BPF_REG_SP, 8), ctx);
	emit(SW64_BPF_STL(r8, SW64_BPF_REG_SP, 16), ctx);
	emit(SW64_BPF_STL(r9, SW64_BPF_REG_SP, 24), ctx);
	emit(SW64_BPF_STL(fp, SW64_BPF_REG_SP, 32), ctx);
	emit(SW64_BPF_STL(tcc, SW64_BPF_REG_SP, 40), ctx);
	emit(SW64_BPF_STL(SW64_BPF_REG_RA, SW64_BPF_REG_SP, 48), ctx);

	/* Set up BPF prog stack base register */
	emit(SW64_BPF_LDI(fp, SW64_BPF_REG_SP, 0), ctx);
	if (!was_classic)
		/* Initialize tail_call_cnt */
		emit(SW64_BPF_LDI(tcc, SW64_BPF_REG_ZR, 0), ctx);

	/* Set up function call stack */
	ctx->stack_size = ctx->prog->aux->stack_depth;
	emit_sw64_ldu32(tmp1, ctx->stack_size, ctx);
	emit(SW64_BPF_SUBL_REG(SW64_BPF_REG_SP, tmp1, SW64_BPF_REG_SP), ctx);
}

static void build_epilogue(struct jit_ctx *ctx)
{
	const int r6 = bpf2sw64[BPF_REG_6];
	const int r7 = bpf2sw64[BPF_REG_7];
	const int r8 = bpf2sw64[BPF_REG_8];
	const int r9 = bpf2sw64[BPF_REG_9];
	const int fp = bpf2sw64[BPF_REG_FP];
	const int tcc = bpf2sw64[TCALL_CNT];
	const int tmp1 = bpf2sw64[TMP_REG_1];

	/* Destroy function call stack */
	emit_sw64_ldu32(tmp1, ctx->stack_size, ctx);
	emit(SW64_BPF_ADDL_REG(SW64_BPF_REG_SP, tmp1, SW64_BPF_REG_SP), ctx);

	/* Restore callee-saved registers */
	emit(SW64_BPF_LDL(r6, SW64_BPF_REG_SP, 0), ctx);
	emit(SW64_BPF_LDL(r7, SW64_BPF_REG_SP, 8), ctx);
	emit(SW64_BPF_LDL(r8, SW64_BPF_REG_SP, 16), ctx);
	emit(SW64_BPF_LDL(r9, SW64_BPF_REG_SP, 24), ctx);
	emit(SW64_BPF_LDL(fp, SW64_BPF_REG_SP, 32), ctx);
	emit(SW64_BPF_LDL(tcc, SW64_BPF_REG_SP, 40), ctx);
	emit(SW64_BPF_LDL(SW64_BPF_REG_RA, SW64_BPF_REG_SP, 48), ctx);
	emit(SW64_BPF_ADDL_REG(SW64_BPF_REG_SP, 56, SW64_BPF_REG_SP), ctx);

	/* Return */
	emit(SW64_BPF_RET(SW64_BPF_REG_RA), ctx);
}

static int out_offset = -1; /* initialized on the first pass of build_body() */
static int emit_bpf_tail_call(struct jit_ctx *ctx)
{
	/* bpf_tail_call(void *prog_ctx, struct bpf_array *array, u64 index) */
	const u8 r2 = bpf2sw64[BPF_REG_2];	/* struct bpf_array *array */
	const u8 r3 = bpf2sw64[BPF_REG_3];	/* u64 index */

	const u8 tmp = bpf2sw64[TMP_REG_1];
	const u8 prg = bpf2sw64[TMP_REG_2];
	const u8 tcc = bpf2sw64[TCALL_CNT];
	const int idx0 = ctx->idx;
#define cur_offset (ctx->idx - idx0)
#define jmp_offset (out_offset - (cur_offset))
	u64 offset;

	/* if (index >= array->map.max_entries)
	 *     goto out;
	 */
	offset = offsetof(struct bpf_array, map.max_entries);
	emit_sw64_ldu64(tmp, offset, ctx);		/* tmp = offset */
	emit(SW64_BPF_ADDL_REG(r2, tmp, tmp), ctx);		/* tmp = r2 + tmp = &map.max_entries */
	emit(SW64_BPF_LDW(tmp, tmp, 0), ctx);		/* tmp = *tmp = map.max_entries */
	emit(SW64_BPF_ZAPNOT_IMM(tmp, 0xf, tmp), ctx);	/* map.max_entries is u32 */
	emit(SW64_BPF_SUBL_REG(r3, tmp, tmp), ctx);		/* tmp = r3 - tmp = index - map.max_entries */
	emit(SW64_BPF_BGE(tmp, jmp_offset), ctx);

	/* if (tail_call_cnt > MAX_TAIL_CALL_CNT)
	 *     goto out;
	 * tail_call_cnt++;
	 */
	emit(SW64_BPF_LDI(tmp, SW64_BPF_REG_ZR, MAX_TAIL_CALL_CNT), ctx);
	emit(SW64_BPF_SUBL_REG(tcc, tmp, tmp), ctx);
	emit(SW64_BPF_BGT(tmp, jmp_offset), ctx);
	emit(SW64_BPF_ADDL_IMM(tcc, 1, tcc), ctx);

	/* prog = array->ptrs[index];
	 * if (prog == NULL)
	 *     goto out;
	 */
	offset = offsetof(struct bpf_array, ptrs);
	emit_sw64_ldu64(tmp, offset, ctx);		/* tmp = offset of ptrs */
	emit(SW64_BPF_ADDL_REG(r2, tmp, tmp), ctx);		/* tmp = r2 + tmp = &ptrs */
	emit(SW64_BPF_SLL_IMM(r3, 3, prg), ctx);		/* prg = r3 * 8, ptrs is 8 bit aligned */
	emit(SW64_BPF_ADDL_REG(tmp, prg, prg), ctx);	/* prg = tmp + prg = &prog */
	emit(SW64_BPF_LDL(prg, prg, 0), ctx);		/* prg = *prg = prog */
	emit(SW64_BPF_BEQ(prg, jmp_offset), ctx);

	/* goto *(prog->bpf_func + prologue_offset); */
	offset = offsetof(struct bpf_prog, bpf_func);
	emit_sw64_ldu64(tmp, offset, ctx);		/* tmp = offset */
	emit(SW64_BPF_ADDL_REG(prg, tmp, tmp), ctx);	/* tmp = prg + tmp = &bpf_func */
	emit(SW64_BPF_LDW(tmp, tmp, 0), ctx);		/* tmp = *tmp = bpf_func */
	emit(SW64_BPF_ZAPNOT_IMM(tmp, 0xf, tmp), ctx);	/* bpf_func is unsigned int */
	emit(SW64_BPF_ADDL_REG(tmp, sizeof(u32) * PROLOGUE_OFFSET, tmp), ctx);
	emit(SW64_BPF_ADDL_REG(SW64_BPF_REG_SP, ctx->stack_size, SW64_BPF_REG_SP), ctx);
	emit(SW64_BPF_BR(tmp, 0), ctx);

	/* out */
	if (out_offset == -1)
		out_offset = cur_offset;
	if (cur_offset != out_offset) {
		pr_err("tail_call out_offset = %d, expected %d!\n",
				cur_offset, out_offset);
		return -1;
	}
	return 0;
#undef cur_offset
#undef jmp_offset
}

/* JITs an eBPF instruction.
 * Returns:
 * 0  - successfully JITed an 8-byte eBPF instruction.
 * >0 - successfully JITed a 16-byte eBPF instruction.
 * <0 - failed to JIT.
 */
static inline int build_insn(const struct bpf_insn *insn, struct jit_ctx *ctx)
{
	const u8 code = insn->code;
	const u8 dst = bpf2sw64[insn->dst_reg];
	const u8 src = bpf2sw64[insn->src_reg];
	const u8 tmp1 = bpf2sw64[TMP_REG_1];
	const u8 tmp2 = bpf2sw64[TMP_REG_2];
	const s16 off = insn->off;
	const s32 imm = insn->imm;
	int jmp_offset;
	u64 func;
	struct bpf_insn insn1;
	u64 imm64;

	switch (code) {
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_X:
		emit(SW64_BPF_LDI(dst, src, 0), ctx);
		break;
	case BPF_ALU | BPF_ADD | BPF_X:
		emit(SW64_BPF_ADDW_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU64 | BPF_ADD | BPF_X:
		emit(SW64_BPF_ADDL_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_X:
		emit(SW64_BPF_SUBW_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU64 | BPF_SUB | BPF_X:
		emit(SW64_BPF_SUBL_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_X:
		emit(SW64_BPF_MULW_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU64 | BPF_MUL | BPF_X:
		emit(SW64_BPF_MULL_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_X:
		emit_sw64_div(dst, src, dst, ctx);
		return -EINVAL;
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_X:
		emit_sw64_mod(dst, src, dst, ctx);
		return -EINVAL;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_X:
		emit(SW64_BPF_SLL_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_X:
		emit(SW64_BPF_ZAPNOT_IMM(dst, 0xf, dst), ctx);
	case BPF_ALU64 | BPF_RSH | BPF_X:
		emit(SW64_BPF_SRL_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_X:
		emit(SW64_BPF_SRA_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_X:
		emit(SW64_BPF_AND_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_X:
	case BPF_ALU64 | BPF_OR | BPF_X:
		emit(SW64_BPF_OR_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_X:
		emit(SW64_BPF_XOR_REG(dst, src, dst), ctx);
		break;
	case BPF_ALU | BPF_NEG:
	case BPF_ALU64 | BPF_NEG:
		emit(SW64_BPF_SEXTB_IMM(0xff, tmp1), ctx);
		emit(SW64_BPF_XOR_IMM(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_END | BPF_TO_LE:
		switch (imm) {
		case 16:
			emit(SW64_BPF_ZAPNOT_IMM(dst, 0x3, dst), ctx);
			break;
		case 32:
			emit(SW64_BPF_ZAPNOT_IMM(dst, 0xf, dst), ctx);
			break;
		case 64:
			break;
		}
	case BPF_ALU | BPF_END | BPF_TO_BE:
		switch (imm) {
		case 16:
			emit_sw64_htobe16(dst, ctx);
			break;
		case 32:
			emit_sw64_htobe32(dst, ctx);
			break;
		case 64:
			emit_sw64_htobe64(dst, ctx);
			break;
		}

	case BPF_ALU | BPF_MOV | BPF_K:
	case BPF_ALU64 | BPF_MOV | BPF_K:
		emit_sw64_lds32(dst, imm, ctx);
		break;
	case BPF_ALU | BPF_ADD | BPF_K:
	case BPF_ALU64 | BPF_ADD | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_ADDL_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_SUB | BPF_K:
	case BPF_ALU64 | BPF_SUB | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_SUBL_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_MUL | BPF_K:
	case BPF_ALU64 | BPF_MUL | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_MULL_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_DIV | BPF_K:
	case BPF_ALU64 | BPF_DIV | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit_sw64_div(dst, src, tmp1, ctx);
		return -EINVAL;
	case BPF_ALU | BPF_MOD | BPF_K:
	case BPF_ALU64 | BPF_MOD | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit_sw64_mod(dst, src, tmp1, ctx);
		return -EINVAL;
	case BPF_ALU | BPF_LSH | BPF_K:
	case BPF_ALU64 | BPF_LSH | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_SLL_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_RSH | BPF_K:
		emit(SW64_BPF_ZAPNOT_IMM(dst, 0xf, dst), ctx);
	case BPF_ALU64 | BPF_RSH | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_SRL_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_ARSH | BPF_K:
	case BPF_ALU64 | BPF_ARSH | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_SRA_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_AND | BPF_K:
	case BPF_ALU64 | BPF_AND | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_AND_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_OR | BPF_K:
	case BPF_ALU64 | BPF_OR | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_OR_REG(dst, tmp1, dst), ctx);
		break;
	case BPF_ALU | BPF_XOR | BPF_K:
	case BPF_ALU64 | BPF_XOR | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		emit(SW64_BPF_XOR_REG(dst, tmp1, dst), ctx);
		break;

	case BPF_JMP | BPF_JA:
		emit(SW64_BPF_BR(SW64_BPF_REG_RA, off), ctx);
		break;

	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JLT | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JLE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSLT | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSLE | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_X:
		switch (BPF_OP(code)) {
		case BPF_JEQ:
			emit(SW64_BPF_CMPEQ_REG(dst, src, tmp1), ctx);
			break;
		case BPF_JGT:
			emit(SW64_BPF_CMPULT_REG(src, dst, tmp1), ctx);
			break;
		case BPF_JLT:
			emit(SW64_BPF_CMPULT_REG(dst, src, tmp1), ctx);
			break;
		case BPF_JGE:
			emit(SW64_BPF_CMPULE_REG(src, dst, tmp1), ctx);
			break;
		case BPF_JLE:
			emit(SW64_BPF_CMPULE_REG(dst, src, tmp1), ctx);
			break;
		case BPF_JNE:
			emit(SW64_BPF_CMPEQ_REG(dst, src, tmp1), ctx);
			emit(SW64_BPF_XOR_IMM(tmp1, 1, tmp1), ctx);
			break;
		case BPF_JSGT:
			emit(SW64_BPF_CMPLT_REG(src, dst, tmp1), ctx);
			break;
		case BPF_JSLT:
			emit(SW64_BPF_CMPLT_REG(dst, src, tmp1), ctx);
			break;
		case BPF_JSGE:
			emit(SW64_BPF_CMPLE_REG(src, dst, tmp1), ctx);
			break;
		case BPF_JSLE:
			emit(SW64_BPF_CMPLE_REG(dst, src, tmp1), ctx);
			break;
		case BPF_JSET:
			emit(SW64_BPF_AND_REG(dst, src, tmp1), ctx);
			break;
		}
		emit(SW64_BPF_BLBS(tmp1, off), ctx);
		break;

	case BPF_JMP | BPF_JEQ | BPF_K:
	case BPF_JMP | BPF_JGT | BPF_K:
	case BPF_JMP | BPF_JLT | BPF_K:
	case BPF_JMP | BPF_JGE | BPF_K:
	case BPF_JMP | BPF_JLE | BPF_K:
	case BPF_JMP | BPF_JNE | BPF_K:
	case BPF_JMP | BPF_JSGT | BPF_K:
	case BPF_JMP | BPF_JSLT | BPF_K:
	case BPF_JMP | BPF_JSGE | BPF_K:
	case BPF_JMP | BPF_JSLE | BPF_K:
	case BPF_JMP | BPF_JSET | BPF_K:
		emit_sw64_lds32(tmp1, imm, ctx);
		switch (BPF_OP(code)) {
		case BPF_JEQ:
			emit(SW64_BPF_CMPEQ_REG(dst, tmp1, tmp1), ctx);
			break;
		case BPF_JGT:
			emit(SW64_BPF_CMPULT_REG(tmp1, dst, tmp1), ctx);
			break;
		case BPF_JLT:
			emit(SW64_BPF_CMPULT_REG(dst, tmp1, tmp1), ctx);
			break;
		case BPF_JGE:
			emit(SW64_BPF_CMPULE_REG(tmp1, dst, tmp1), ctx);
			break;
		case BPF_JLE:
			emit(SW64_BPF_CMPULE_REG(dst, tmp1, tmp1), ctx);
			break;
		case BPF_JNE:
			emit(SW64_BPF_CMPEQ_REG(dst, tmp1, tmp1), ctx);
			emit(SW64_BPF_XOR_IMM(tmp1, 1, tmp1), ctx);
			break;
		case BPF_JSGT:
			emit(SW64_BPF_CMPLT_REG(tmp1, dst, tmp1), ctx);
			break;
		case BPF_JSLT:
			emit(SW64_BPF_CMPLT_REG(dst, tmp1, tmp1), ctx);
			break;
		case BPF_JSGE:
			emit(SW64_BPF_CMPLE_REG(tmp1, dst, tmp1), ctx);
			break;
		case BPF_JSLE:
			emit(SW64_BPF_CMPLE_REG(dst, tmp1, tmp1), ctx);
			break;
		case BPF_JSET:
			emit(SW64_BPF_AND_REG(dst, tmp1, tmp1), ctx);
			break;
		}
		emit(SW64_BPF_BLBS(tmp1, off), ctx);
		break;

	case BPF_JMP | BPF_CALL:
		func = (u64)__bpf_call_base + imm;
		emit_sw64_ldu64(tmp1, func, ctx);
		emit(SW64_BPF_CALL(SW64_BPF_REG_RA, tmp1), ctx);
		break;

	case BPF_JMP | BPF_TAIL_CALL:
		if (emit_bpf_tail_call(ctx))
			return -EFAULT;
		break;

	case BPF_JMP | BPF_EXIT:
		if (insn - ctx->prog->insnsi + 1 == ctx->prog->len)
			break;
		jmp_offset = (offset_to_epilogue(ctx) - 1) * 4;
		// emit(SW64_BPF_BR(SW64_BPF_REG_ZR, jmp_offset), ctx);
		// break;
		emit_sw64_lds32(tmp1, jmp_offset, ctx);
		emit(SW64_BPF_BR(tmp2, 0), ctx);
		emit(SW64_BPF_ADDL_REG(tmp1, tmp2, tmp1), ctx);
		emit(SW64_BPF_JMP(SW64_BPF_REG_ZR, tmp1), ctx);
		break;

	case BPF_LD | BPF_IMM | BPF_DW:
		insn1 = insn[1];
		imm64 = (u64)insn1.imm << 32 | (u32)imm;
		emit_sw64_ldu64(dst, imm64, ctx);

		return 1;

	/* LDX: dst = *(size *)(src + off) */
	case BPF_LDX | BPF_MEM | BPF_W:
		emit(SW64_BPF_LDW(dst, src, off), ctx);
		break;
	case BPF_LDX | BPF_MEM | BPF_H:
		emit(SW64_BPF_LDHU(dst, src, off), ctx);
		emit(SW64_BPF_SEXTH_REG(dst, dst), ctx);
		break;
	case BPF_LDX | BPF_MEM | BPF_B:
		emit(SW64_BPF_LDBU(dst, src, off), ctx);
		emit(SW64_BPF_SEXTB_REG(dst, dst), ctx);
		break;
	case BPF_LDX | BPF_MEM | BPF_DW:
		emit(SW64_BPF_LDW(dst, src, off), ctx);
		break;

	/* ST: *(size *)(dst + off) = imm */
	case BPF_ST | BPF_MEM | BPF_W:
	case BPF_ST | BPF_MEM | BPF_H:
	case BPF_ST | BPF_MEM | BPF_B:
	case BPF_ST | BPF_MEM | BPF_DW:
		/* Load imm to a register then store it */
		emit_sw64_lds32(tmp1, imm, ctx);
		switch (BPF_SIZE(code)) {
		case BPF_W:
			emit(SW64_BPF_STW(tmp1, dst, off), ctx);
			break;
		case BPF_H:
			emit(SW64_BPF_STH(tmp1, dst, off), ctx);
			break;
		case BPF_B:
			emit(SW64_BPF_STB(tmp1, dst, off), ctx);
			break;
		case BPF_DW:
			emit(SW64_BPF_STL(tmp1, dst, off), ctx);
			break;
		}
		break;

	/* STX: *(size *)(dst + off) = src */
	case BPF_STX | BPF_MEM | BPF_W:
		emit(SW64_BPF_STW(src, dst, off), ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_H:
		emit(SW64_BPF_STW(src, dst, off), ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_B:
		emit(SW64_BPF_STW(src, dst, off), ctx);
		break;
	case BPF_STX | BPF_MEM | BPF_DW:
		emit(SW64_BPF_STW(src, dst, off), ctx);
		break;

	/* STX XADD: lock *(u32 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_W:
		emit(SW64_BPF_LDW(tmp1, dst, off), ctx);
		emit(SW64_BPF_ADDW_REG(tmp1, src, tmp1), ctx);
		emit(SW64_BPF_STW(tmp1, dst, off), ctx);
		break;
	/* STX XADD: lock *(u64 *)(dst + off) += src */
	case BPF_STX | BPF_XADD | BPF_DW:
		emit(SW64_BPF_LDL(tmp1, dst, off), ctx);
		emit(SW64_BPF_ADDL_REG(tmp1, src, tmp1), ctx);
		emit(SW64_BPF_STL(tmp1, dst, off), ctx);
		break;

	default:
		pr_err("unknown opcode %02x\n", code);
		return -EINVAL;
	}

	return 0;
}

static int build_body(struct jit_ctx *ctx)
{
	const struct bpf_prog *prog = ctx->prog;
	int i;

	for (i = 0; i < prog->len; i++) {
		const struct bpf_insn *insn = &prog->insnsi[i];
		int ret;

		ret = build_insn(insn, ctx);
		if (ret > 0) {
			i++;
			if (ctx->image == NULL)
				ctx->insn_offset[i] = ctx->idx;
			continue;
		}
		if (ctx->image == NULL)
			ctx->insn_offset[i] = ctx->idx;
		if (ret)
			return ret;
	}

	return 0;
}

static int validate_code(struct jit_ctx *ctx)
{
	int i;

	for (i = 0; i < ctx->idx; i++) {
		if (ctx->image[i] == SW64_BPF_ILLEGAL_INSN)
			return -1;
	}

	return 0;
}

static inline void bpf_flush_icache(void *start, void *end)
{
	flush_icache_range((unsigned long)start, (unsigned long)end);
}

struct bpf_prog *bpf_int_jit_compile(struct bpf_prog *prog)
{
	struct bpf_prog *tmp, *orig_prog = prog;
	struct bpf_binary_header *header;
	struct sw64_jit_data *jit_data;
	bool was_classic = bpf_prog_was_classic(prog);
	bool tmp_blinded = false;
	bool extra_pass = false;
	struct jit_ctx ctx;
	int image_size;
	u8 *image_ptr;

	if (!prog->jit_requested)
		return orig_prog;

	tmp = bpf_jit_blind_constants(prog);
	/* If blinding was requested and we failed during blinding,
	 * we must fall back to the interpreter.
	 */
	if (IS_ERR(tmp))
		return orig_prog;
	if (tmp != prog) {
		tmp_blinded = true;
		prog = tmp;
	}

	jit_data = prog->aux->jit_data;
	if (!jit_data) {
		jit_data = kzalloc(sizeof(*jit_data), GFP_KERNEL);
		if (!jit_data) {
			prog = orig_prog;
			goto out;
		}
		prog->aux->jit_data = jit_data;
	}
	if (jit_data->ctx.insn_offset) {
		ctx = jit_data->ctx;
		image_ptr = jit_data->image;
		header = jit_data->header;
		extra_pass = true;
		image_size = sizeof(u32) * ctx.idx;
		goto skip_init_ctx;
	}
	memset(&ctx, 0, sizeof(ctx));
	ctx.prog = prog;

	ctx.insn_offset = kcalloc(prog->len, sizeof(int), GFP_KERNEL);
	if (ctx.insn_offset == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 1. Initial fake pass to compute ctx->idx. */

	/* Fake pass to fill in ctx->offset. */
	build_prologue(&ctx, was_classic);

	if (build_body(&ctx)) {
		prog = orig_prog;
		goto out_off;
	}

	ctx.epilogue_offset = ctx.idx;
	build_epilogue(&ctx);

	/* Now we know the actual image size. */
	image_size = sizeof(u32) * ctx.idx;
	header = bpf_jit_binary_alloc(image_size, &image_ptr,
				      sizeof(u32), jit_fill_hole);
	if (header == NULL) {
		prog = orig_prog;
		goto out_off;
	}

	/* 2. Now, the actual pass. */

	ctx.image = (u32 *)image_ptr;
skip_init_ctx:
	ctx.idx = 0;

	build_prologue(&ctx, was_classic);

	if (build_body(&ctx)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	build_epilogue(&ctx);

	/* 3. Extra pass to validate JITed code. */
	if (validate_code(&ctx)) {
		bpf_jit_binary_free(header);
		prog = orig_prog;
		goto out_off;
	}

	/* And we're done. */
	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, image_size, 2, ctx.image);

	bpf_flush_icache(header, ctx.image + ctx.idx);

	if (!prog->is_func || extra_pass) {
		bpf_jit_binary_lock_ro(header);
	} else {
		jit_data->ctx = ctx;
		jit_data->image = image_ptr;
		jit_data->header = header;
	}
	prog->bpf_func = (void *)ctx.image;
	prog->jited = 1;
	prog->jited_len = image_size;

	if (!prog->is_func || extra_pass) {
out_off:
		kfree(ctx.insn_offset);
		kfree(jit_data);
		prog->aux->jit_data = NULL;
	}
out:
	if (tmp_blinded)
		bpf_jit_prog_release_other(prog, prog == orig_prog ?
					   tmp : orig_prog);
	return prog;
}
