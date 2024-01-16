// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/errno.h>
#include <linux/err.h>
#include <linux/ktime.h>
#include <linux/kvm_host.h>
#include <linux/vmalloc.h>
#include <linux/fs.h>
#include <linux/random.h>
#include <asm/page.h>
#include <asm/cacheflush.h>
#include <asm/cacheops.h>
#include <asm/cpu-info.h>
#include <asm/mmu_context.h>
#include <asm/tlbflush.h>
#include <asm/inst.h>
#include "kvmcpu.h"
#include "trace.h"

int _kvm_emu_idle(struct kvm_vcpu *vcpu)
{
	++vcpu->stat.idle_exits;
	trace_kvm_exit(vcpu, KVM_TRACE_EXIT_IDLE);

	kvm_vcpu_block(vcpu);
	kvm_clear_request(KVM_REQ_UNHALT, vcpu);
	return EMULATE_DONE;
}

int _kvm_emu_mmio_write(struct kvm_vcpu *vcpu, union loongarch_instruction inst)
{
	struct kvm_run *run = vcpu->run;
	unsigned int rd, op8, opcode;
	unsigned long rd_val = 0;
	void *data = run->mmio.data;
	unsigned long curr_pc;
	int ret = 0;

	/*
	 * Update PC and hold onto current PC in case there is
	 * an error and we want to rollback the PC
	 */
	curr_pc = vcpu->arch.pc;
	update_pc(&vcpu->arch);

	op8 = (inst.word >> 24) & 0xff;
	run->mmio.phys_addr = vcpu->arch.badv;
	if (run->mmio.phys_addr == KVM_INVALID_ADDR)
		goto out_fail;

	if (op8 < 0x28) {
		/* stptrw/d process */
		rd = inst.reg2i14_format.rd;
		opcode = inst.reg2i14_format.opcode;

		switch (opcode) {
		case stptrd_op:
			run->mmio.len = 8;
			*(unsigned long *)data = vcpu->arch.gprs[rd];
			break;
		case stptrw_op:
			run->mmio.len = 4;
			*(unsigned int *)data = vcpu->arch.gprs[rd];
			break;
		default:
			break;
		}
	} else if (op8 < 0x30) {
		/* st.b/h/w/d  process */
		rd = inst.reg2i12_format.rd;
		opcode = inst.reg2i12_format.opcode;
		rd_val = vcpu->arch.gprs[rd];

		switch (opcode) {
		case std_op:
			run->mmio.len = 8;
			*(unsigned long *)data = rd_val;
			break;
		case stw_op:
			run->mmio.len = 4;
			*(unsigned int *)data = rd_val;
			break;
		case sth_op:
			run->mmio.len = 2;
			*(unsigned short *)data = rd_val;
			break;
		case stb_op:
			run->mmio.len = 1;
			*(unsigned char *)data = rd_val;
			break;
		default:
			kvm_err("Store not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			goto out_fail;
		}
	} else if (op8 == 0x38) {
		/* stxb/h/w/d process */
		rd = inst.reg3_format.rd;
		opcode = inst.reg3_format.opcode;

		switch (opcode) {
		case stxb_op:
			run->mmio.len = 1;
			*(unsigned char *)data = vcpu->arch.gprs[rd];
			break;
		case stxh_op:
			run->mmio.len = 2;
			*(unsigned short *)data = vcpu->arch.gprs[rd];
			break;
		case stxw_op:
			run->mmio.len = 4;
			*(unsigned int *)data = vcpu->arch.gprs[rd];
			break;
		case stxd_op:
			run->mmio.len = 8;
			*(unsigned long *)data = vcpu->arch.gprs[rd];
			break;
		default:
			kvm_err("Store not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			goto out_fail;
		}
	} else {
		kvm_err("Store not yet supporded (inst=0x%08x)\n",
			inst.word);
		kvm_arch_vcpu_dump_regs(vcpu);
		goto out_fail;
	}

	/* All MMIO emulate in kernel go through the common interface */
	ret = kvm_io_bus_write(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
				run->mmio.len, data);
	if (!ret) {
		vcpu->mmio_needed = 0;
		return EMULATE_DONE;
	}

	run->mmio.is_write = 1;
	vcpu->mmio_needed = 1;
	vcpu->mmio_is_write = 1;

	return EMULATE_DO_MMIO;

out_fail:
	/* Rollback PC if emulation was unsuccessful */
	vcpu->arch.pc = curr_pc;
	return EMULATE_FAIL;
}

int _kvm_emu_mmio_read(struct kvm_vcpu *vcpu, union loongarch_instruction inst)
{
	unsigned int op8, opcode, rd;
	int ret = 0;
	struct kvm_run *run = vcpu->run;

	run->mmio.phys_addr = vcpu->arch.badv;
	if (run->mmio.phys_addr == KVM_INVALID_ADDR)
		return EMULATE_FAIL;

	vcpu->mmio_needed = 2;	/* signed */
	op8 = (inst.word >> 24) & 0xff;

	if (op8 < 0x28) {
		/* ldptr.w/d process */
		rd = inst.reg2i14_format.rd;
		opcode = inst.reg2i14_format.opcode;

		switch (opcode) {
		case ldptrd_op:
			run->mmio.len = 8;
			break;
		case ldptrw_op:
			run->mmio.len = 4;
			break;
		default:
			break;
		}
	} else if (op8 < 0x2f) {
		/* ld.b/h/w/d, ld.bu/hu/wu process */
		rd = inst.reg2i12_format.rd;
		opcode = inst.reg2i12_format.opcode;

		switch (opcode) {
		case ldd_op:
			run->mmio.len = 8;
			break;
		case ldwu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 4;
			break;
		case ldw_op:
			run->mmio.len = 4;
			break;
		case ldhu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 2;
			break;
		case ldh_op:
			run->mmio.len = 2;
			break;
		case ldbu_op:
			vcpu->mmio_needed = 1;	/* unsigned */
			run->mmio.len = 1;
			break;
		case ldb_op:
			run->mmio.len = 1;
			break;
		default:
			kvm_err("Load not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			vcpu->mmio_needed = 0;
			return EMULATE_FAIL;
		}
	} else if (op8 == 0x38) {
		/* ldxb/h/w/d, ldxb/h/wu, ldgtb/h/w/d, ldleb/h/w/d process */
		rd = inst.reg3_format.rd;
		opcode = inst.reg3_format.opcode;

		switch (opcode) {
		case ldxb_op:
			run->mmio.len = 1;
			break;
		case ldxbu_op:
			run->mmio.len = 1;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxh_op:
			run->mmio.len = 2;
			break;
		case ldxhu_op:
			run->mmio.len = 2;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxw_op:
			run->mmio.len = 4;
			break;
		case ldxwu_op:
			run->mmio.len = 4;
			vcpu->mmio_needed = 1;	/* unsigned */
			break;
		case ldxd_op:
			run->mmio.len = 8;
			break;
		default:
			kvm_err("Load not yet supporded (inst=0x%08x)\n",
				inst.word);
			kvm_arch_vcpu_dump_regs(vcpu);
			vcpu->mmio_needed = 0;
			return EMULATE_FAIL;
		}
	} else {
		kvm_err("Load not yet supporded (inst=0x%08x) @ %lx\n",
			inst.word, vcpu->arch.pc);
		vcpu->mmio_needed = 0;
		return EMULATE_FAIL;
	}

	/* Set for _kvm_complete_mmio_read use */
	vcpu->arch.io_gpr = rd;
	ret = kvm_io_bus_read(vcpu, KVM_MMIO_BUS, run->mmio.phys_addr,
						run->mmio.len, run->mmio.data);
	run->mmio.is_write = 0;
	vcpu->mmio_is_write = 0;

	if (!ret) {
		_kvm_complete_mmio_read(vcpu, run);
		vcpu->mmio_needed = 0;
		return EMULATE_DONE;
	}
	return EMULATE_DO_MMIO;
}

int _kvm_complete_mmio_read(struct kvm_vcpu *vcpu, struct kvm_run *run)
{
	unsigned long *gpr = &vcpu->arch.gprs[vcpu->arch.io_gpr];
	enum emulation_result er = EMULATE_DONE;

	/* update with new PC */
	update_pc(&vcpu->arch);
	switch (run->mmio.len) {
	case 8:
		*gpr = *(s64 *)run->mmio.data;
		break;

	case 4:
		if (vcpu->mmio_needed == 2)
			*gpr = *(int *)run->mmio.data;
		else
			*gpr = *(unsigned int *)run->mmio.data;
		break;

	case 2:
		if (vcpu->mmio_needed == 2)
			*gpr = *(short *) run->mmio.data;
		else
			*gpr = *(unsigned short *)run->mmio.data;

		break;
	case 1:
		if (vcpu->mmio_needed == 2)
			*gpr = *(char *) run->mmio.data;
		else
			*gpr = *(unsigned char *) run->mmio.data;
		break;
	default:
		kvm_err("Bad MMIO length: %d,addr is 0x%lx",
				run->mmio.len, vcpu->arch.badv);
		er = EMULATE_FAIL;
		break;
	}

	return er;
}
