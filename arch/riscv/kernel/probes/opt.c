// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Kernel Probes Jump Optimization (Optprobes)
 *
 * Copyright (C) IBM Corporation, 2002, 2004
 * Copyright (C) Hitachi Ltd., 2012
 * Copyright (C) Huawei Inc., 2014
 * Copyright (C) Guokai Chen, 2022
 * Author: Guokai Chen chenguokai17@mails.ucas.ac.cn
 */

#include <linux/kprobes.h>
#include <linux/jump_label.h>
#include <linux/extable.h>
#include <linux/stop_machine.h>
#include <linux/moduleloader.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <asm/cacheflush.h>
/* for patch_text */
#include <linux/ftrace.h>
#include <asm/patch.h>
#include "simulate-insn.h"
#include "decode-insn.h"

/*
 * If the probed instruction doesn't use PC and is not system or fence
 * we can copy it into template and have it executed directly without
 * simulation or emulation.
 */
static enum probe_insn __kprobes can_kprobe_direct_exec(kprobe_opcode_t *addr)
{
	/*
	 * instructions that use PC like: branch jump auipc
	 * instructions that belongs to system or fence like ebreak ecall fence.i
	 */
	kprobe_opcode_t inst = *addr;

	RISCV_INSN_REJECTED(system, inst);
	RISCV_INSN_REJECTED(fence, inst);
	RISCV_INSN_REJECTED(branch, inst);
	RISCV_INSN_REJECTED(jal, inst);
	RISCV_INSN_REJECTED(jalr, inst);
	RISCV_INSN_REJECTED(auipc, inst);
	return INSN_GOOD;
}

#define TMPL_VAL_IDX \
	((kprobe_opcode_t *)optprobe_template_val - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_CALL_IDX \
	((kprobe_opcode_t *)optprobe_template_call - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_STORE_EPC_IDX \
	((kprobe_opcode_t *)optprobe_template_store_epc - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_END_IDX \
	((kprobe_opcode_t *)optprobe_template_end - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_ADD_SP \
	((kprobe_opcode_t *)optprobe_template_add_sp - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_SUB_SP \
	((kprobe_opcode_t *)optprobe_template_sub_sp - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_RESTORE_BEGIN \
	((kprobe_opcode_t *)optprobe_template_restore_begin - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_RESTORE_ORIGN_INSN \
	((kprobe_opcode_t *)optprobe_template_restore_orig_insn - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_RESTORE_RET \
	((kprobe_opcode_t *)optprobe_template_ret - \
	 (kprobe_opcode_t *)optprobe_template_entry)
#define TMPL_RESTORE_END \
	((kprobe_opcode_t *)optprobe_template_restore_end - \
	 (kprobe_opcode_t *)optprobe_template_entry)

#define FREE_SEARCH_DEPTH 32

/*
 * RISC-V can always optimize an instruction if not null
 */
int arch_prepared_optinsn(struct arch_optimized_insn *optinsn)
{
	return optinsn->insn != NULL;
}

/*
 * In RISC-V ISA, jal has a quite limited jump range, To achive adequate
 * range, auipc+jalr pair is utilized. It requires a replacement of two
 * instructions, thus next instruction should be examined.
 */
int arch_check_optimized_kprobe(struct optimized_kprobe *op)
{
	struct kprobe *p;

	/* check if the next instruction has a kprobe */
	p = get_kprobe(op->kp.addr + 1);
	if (p && !kprobe_disabled(p))
		return -EEXIST;

	return 0;
}

/*
 * In RISC-V ISA, auipc+jalr requires a free register
 * Inspired by register renaming in OoO processor, we search backwards
 * to find such a register that is not previously used as a source
 * register and is used as a destination register before any branch or
 * jump instruction.
 */
static int
__arch_find_free_register(kprobe_opcode_t *addr, int use_orig,
			  kprobe_opcode_t orig)
{
	int i, rs1, rs2, rd;
	kprobe_opcode_t inst;
	int rs_mask = 0;

	for (i = 0; i < FREE_SEARCH_DEPTH; i++) {
		if (i == 0 && use_orig)
			inst = orig;
		else
			inst = *(kprobe_opcode_t *)(addr + i);
		/*
		 * Detailed handling:
		 * jalr/branch/system: must have reached the end, no result
		 * jal: if not chosen as result, must have reached the end
		 * arithmetic/load/store: record their rs
		 * jal/arithmetic/load: if proper rd found, return result
		 * others (float point/vector): ignore
		 */
		if (riscv_insn_is_branch(inst) || riscv_insn_is_jalr(inst) ||
		    riscv_insn_is_system(inst)) {
			return 0;
		}
		/* instructions that has rs1 */
		if (riscv_insn_is_arith_ri(inst) || riscv_insn_is_arith_rr(inst) ||
		    riscv_insn_is_load(inst) || riscv_insn_is_store(inst) ||
		    riscv_insn_is_amo(inst)) {
			rs1 = (inst & 0xF8000) >> 15;
			rs_mask |= 1 << rs1;
		}
		/* instructions that has rs2 */
		if (riscv_insn_is_arith_rr(inst) || riscv_insn_is_store(inst) ||
		    riscv_insn_is_amo(inst)) {
			rs2 = (inst & 0x1F00000) >> 20;
			rs_mask |= 1 << rs2;
		}
		/* instructions that has rd */
		if (riscv_insn_is_lui(inst) || riscv_insn_is_jal(inst) ||
		    riscv_insn_is_load(inst) || riscv_insn_is_arith_ri(inst) ||
		    riscv_insn_is_arith_rr(inst) || riscv_insn_is_amo(inst)) {
			rd = (inst & 0xF80) >> 7;
			if (rd != 0 && (rs_mask & (1 << rd)) == 0)
				return rd;
			if (riscv_insn_is_jal(inst))
				return 0;
		}
	}
	return 0;
}

/*
 * If two free registers can be found at the beginning of both
 * the start and the end of replaced code, it can be optimized
 * Also, in-function jumps need to be checked to make sure that
 * there is no jump to the second instruction to be replaced
 */

static int can_optimize(unsigned long paddr, kprobe_opcode_t orig)
{
	unsigned long addr, size = 0, offset = 0, target;
	s32 imm;
	kprobe_opcode_t inst;

	if (!kallsyms_lookup_size_offset(paddr, &size, &offset))
		return 0;

	addr = paddr - offset;

	/* if there are not enough space for our kprobe, skip */
	if (addr + size <= paddr + MAX_OPTIMIZED_LENGTH)
		return 0;

	while (addr < paddr - offset + size) {
		/* Check from the start until the end */
		inst = *(kprobe_opcode_t *)addr;
		/* branch and jal is capable of determing target before execution */
		if (riscv_insn_is_branch(inst)) {
			imm = branch_offset(inst);
			target = addr + imm;
			if (target == paddr + RVI_INST_SIZE)
				return 0;
		} else if (riscv_insn_is_jal(inst)) {
			imm = jal_offset(inst);
			target = addr + imm;
			if (target == paddr + RVI_INST_SIZE)
				return 0;
		}
		/* RVI is always 4 byte long */
		addr += RVI_INST_SIZE;
	}

	if (can_kprobe_direct_exec((kprobe_opcode_t *)(paddr + 4)) != INSN_GOOD ||
	    can_kprobe_direct_exec(&orig) != INSN_GOOD)
		return 0;

	/* only valid when we find two free registers, the first of which stores
	 * detour buffer entry address and the second one stores the return address
	 * that is two instructions after the probe point
	 */
	return __arch_find_free_register((kprobe_opcode_t *)paddr, 1, orig) &&
			__arch_find_free_register((kprobe_opcode_t *)paddr + MAX_COPIED_INSN, 0, 0);
}

/* Free optimized instruction slot */
static void
__arch_remove_optimized_kprobe(struct optimized_kprobe *op, int dirty)
{
	if (op->optinsn.insn) {
		free_optinsn_slot(op->optinsn.insn, dirty);
		op->optinsn.insn = NULL;
	}
}

static void
optimized_callback(struct optimized_kprobe *op, struct pt_regs *regs)
{
	unsigned long flags;
	struct kprobe_ctlblk *kcb;

	/* Save skipped registers */
	regs->epc = (unsigned long)op->kp.addr;
	regs->orig_a0 = ~0UL;

	local_irq_save(flags);
	kcb = get_kprobe_ctlblk();

	if (kprobe_running()) {
		kprobes_inc_nmissed_count(&op->kp);
	} else {
		__this_cpu_write(current_kprobe, &op->kp);
		kcb->kprobe_status = KPROBE_HIT_ACTIVE;
		opt_pre_handler(&op->kp, regs);
		__this_cpu_write(current_kprobe, NULL);
	}
	local_irq_restore(flags);
}

NOKPROBE_SYMBOL(optimized_callback)

/*
 * R-type instruction as an example for the following patch functions
 * 31   24 25 20 19 15 14    12 11 7 6     0
 * funct7 | rs2 | rs1 | funct3 | rd | opcode
 *    7      5     5       3      5     7
 */

#define RISCV_RD_CLEAR 0xfffff07fUL
#define RISCV_RS1_CLEAR 0xfff07fffUL
#define RISCV_RS2_CLEAR 0xfe0fffffUL
#define RISCV_RD_SHIFT 7
#define RISCV_RS1_SHIFT 15
#define RISCV_RS2_SHIFT 20

static inline kprobe_opcode_t
__arch_patch_rd(kprobe_opcode_t inst, unsigned long val)
{
	inst &= RISCV_RD_CLEAR;
	inst |= val << RISCV_RD_SHIFT;
	return inst;
}

static inline kprobe_opcode_t
__arch_patch_rs1(kprobe_opcode_t inst, unsigned long val)
{
	inst &= RISCV_RS1_CLEAR;
	inst |= val << RISCV_RS1_SHIFT;
	return inst;
}

static inline kprobe_opcode_t __arch_patch_rs2(kprobe_opcode_t inst,
					       unsigned long val)
{
	inst &= RISCV_RS2_CLEAR;
	inst |= val << RISCV_RS2_SHIFT;
	return inst;
}

int arch_prepare_optimized_kprobe(struct optimized_kprobe *op, struct kprobe *orig)
{
	kprobe_opcode_t *code, *detour_slot, *detour_ret_addr;
	long rel_chk;
	unsigned long val;
	int ret = 0;

	if (!can_optimize((unsigned long)orig->addr, orig->opcode))
		return -EILSEQ;

	code = kzalloc(MAX_OPTINSN_SIZE, GFP_KERNEL);
	detour_slot = get_optinsn_slot();

	if (!code || !detour_slot) {
		ret = -ENOMEM;
		goto on_err;
	}

	/*
	 * Verify if the address gap is within 4GB range, because this uses
	 * a auipc+jalr pair.
	 */
	rel_chk = (long)detour_slot - (long)orig->addr + 8;
	if (abs(rel_chk) > U32_MAX) {
		/*
		 * Different from x86, we free code buf directly instead of
		 * calling __arch_remove_optimized_kprobe() because
		 * we have not fill any field in op.
		 */
		ret = -ERANGE;
		goto on_err;
	}

	/* Copy arch-dep-instance from template. */
	memcpy(code, (unsigned long *)optprobe_template_entry,
	       TMPL_END_IDX * sizeof(kprobe_opcode_t));

	/* Set probe information */
	*(unsigned long *)(&code[TMPL_VAL_IDX]) = (unsigned long)op;

	/* Set probe function call */
	*(unsigned long *)(&code[TMPL_CALL_IDX]) = (unsigned long)optimized_callback;

	/* The free register to which the EPC (return address) is stored,
	 * is dynamically allocated during opt probe setup. For every different
	 * probe address, epc is stored in a possibly different register,
	 * which need to be patched to reflect the real source.
	 * rs2 of optprobe_template_store_epc is the source register.
	 * After patch, optprobe_template_store_epc will be
	 * REG_S free_register, PT_EPC(sp)
	 */
	code[TMPL_STORE_EPC_IDX] =
		__arch_patch_rs2(code[TMPL_STORE_EPC_IDX],
				 __arch_find_free_register(orig->addr, 1, orig->opcode));

	/* Adjust return temp register */
	val =
		__arch_find_free_register(orig->addr +
					  MAX_COPIED_INSN, 0,
					  0);
	/*
	 * Patch of optprobe_template_restore_end
	 * patch:
	 *   rd and imm of auipc
	 *   rs1 and imm of jalr
	 * after patch:
	 *   auipc free_register, %hi(return_address)
	 *   jalr x0, %lo(return_address)(free_register)
	 *
	 */

	detour_ret_addr = &detour_slot[optprobe_template_restore_end - optprobe_template_entry];

	make_call(detour_ret_addr, (orig->addr + MAX_COPIED_INSN),
		  (code + TMPL_RESTORE_END));
	code[TMPL_RESTORE_END] = __arch_patch_rd(code[TMPL_RESTORE_END], val);
	code[TMPL_RESTORE_END + 1] =
		__arch_patch_rs1(code[TMPL_RESTORE_END + 1], val);
	code[TMPL_RESTORE_END + 1] = __arch_patch_rd(code[TMPL_RESTORE_END + 1], 0);

	/* Copy insn and have it executed during restore */

	code[TMPL_RESTORE_ORIGN_INSN] = orig->opcode;
	code[TMPL_RESTORE_ORIGN_INSN + 1] =
		*(kprobe_opcode_t *)(orig->addr + 1);

	if (patch_text_nosync(detour_slot, code, MAX_OPTINSN_SIZE)) {
		ret = -EPERM;
		goto on_err;
	}

	kfree(code);
	/* Set op->optinsn.insn means prepared. */
	op->optinsn.insn = detour_slot;
	return ret;

on_err:
	kfree(code);
	if (detour_slot)
		free_optinsn_slot(detour_slot, 0);
	return ret;
}

struct patch_probe {
	void *addr;
	void *insns;
	size_t len;
	atomic_t cpu_count;
};

static int patch_text_stop_machine(void *data)
{
	struct patch_probe *arg = data;
	int ret = 0;

	if (atomic_inc_return(&arg->cpu_count) == num_online_cpus()) {
		ret = patch_text_nosync(arg->addr, arg->insns, arg->len);
		atomic_inc(&arg->cpu_count);
	} else {
		while (atomic_read(&arg->cpu_count) <= num_online_cpus())
			cpu_relax();
		/* ensure patch visibility */
		smp_mb();
	}

	return ret;
}

void __kprobes arch_optimize_kprobes(struct list_head *oplist)
{
	struct optimized_kprobe *op, *tmp;
	kprobe_opcode_t val;
	struct patch_probe pp;

	list_for_each_entry_safe(op, tmp, oplist, list) {
		kprobe_opcode_t insn[MAX_COPIED_INSN];

		WARN_ON(kprobe_disabled(&op->kp));

		/*
		 * Backup instructions which will be replaced
		 * by jump address
		 */
		memcpy(op->optinsn.copied_insn, op->kp.addr, JUMP_SIZE);
		op->optinsn.copied_insn[0] = op->kp.opcode;

		make_call(op->kp.addr, op->optinsn.insn, insn);

		/*
		 * Extract free register from the third instruction of
		 * detour buffer (rs2 of REG_S free_register, PT_EPC(sp))
		 * to save another call of __arch_find_free_register
		 */
		val = (op->optinsn.insn[2] & 0x1F00000) >> 20;

		/*
		 * After patch, it should be:
		 * auipc free_register, %hi(detour_buffer)
		 * jalr free_register, free_register, %lo(detour_buffer)
		 * where free_register will eventually save the return address
		 */
		insn[0] = __arch_patch_rd(insn[0], val);
		insn[1] = __arch_patch_rd(insn[1], val);
		insn[1] = __arch_patch_rs1(insn[1], val);

		/*
		 * Similar to __arch_disarm_kprobe, operations which
		 * removing breakpoints must be wrapped by stop_machine
		 * to avoid racing.
		 */
		pp = (struct patch_probe){
			.addr = op->kp.addr,
			.insns = insn,
			.len = JUMP_SIZE,
			.cpu_count = ATOMIC_INIT(0),
		};
		WARN_ON(stop_machine_cpuslocked(patch_text_stop_machine, &pp, cpu_online_mask));

		list_del_init(&op->list);
	}
}

static int arch_disarm_kprobe_opt(void *vop)
{
	struct optimized_kprobe *op = (struct optimized_kprobe *)vop;
	struct patch_probe pp = {
		.addr = op->kp.addr,
		.insns = op->optinsn.copied_insn,
		.len = JUMP_SIZE,
		.cpu_count = ATOMIC_INIT(0),
	};
	WARN_ON(stop_machine_cpuslocked(patch_text_stop_machine, &pp, cpu_online_mask));
	arch_arm_kprobe(&op->kp);
	return 0;
}

void arch_unoptimize_kprobe(struct optimized_kprobe *op)
{
	arch_disarm_kprobe_opt((void *)op);
}

/*
 * Recover original instructions and breakpoints from relative jumps.
 * Caller must call with locking kprobe_mutex.
 */
void arch_unoptimize_kprobes(struct list_head *oplist,
			     struct list_head *done_list)
{
	struct optimized_kprobe *op, *tmp;

	list_for_each_entry_safe(op, tmp, oplist, list) {
		arch_unoptimize_kprobe(op);
		list_move(&op->list, done_list);
	}
}

int arch_within_optimized_kprobe(struct optimized_kprobe *op,
				 unsigned long addr)
{
	return (op->kp.addr <= addr &&
		op->kp.addr + (JUMP_SIZE / sizeof(kprobe_opcode_t)) > addr);
}

void arch_remove_optimized_kprobe(struct optimized_kprobe *op)
{
	__arch_remove_optimized_kprobe(op, 1);
}
