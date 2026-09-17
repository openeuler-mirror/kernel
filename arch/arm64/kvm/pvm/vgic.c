// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Yang Qinxiong <yangqinxiong@huawei.com>
 */

/*
 * PVM supports only Linux guests using Group 1 interrupts. All Group 0
 * functionality is outside the supported guest configuration, including
 * its CPU-interface state and register operations, interrupt delivery,
 * and FIQ injection. Existing Group 0 register accessors do not imply
 * support for Group 0 functionality.
 */

#include <linux/irqchip/arm-gic-v3.h>
#include <linux/kvm_host.h>
#include <linux/minmax.h>

#include <kvm/arm_vgic.h>

#include <asm/kvm_pvm.h>
#include <asm/sysreg.h>

#include "../vgic/vgic.h"

#define PVM_VGIC_IDLE_PRIORITY	0xff
#define PVM_VGIC_INTID_MASK	GENMASK(23, 0)

static unsigned int pvm_vgic_bpr_min(struct kvm_vcpu *vcpu)
{
	unsigned int pri_bits = vcpu->arch.vgic_cpu.num_pri_bits;

	/* APxR0 alone represents the 32 levels advertised by PVM. */
	BUILD_BUG_ON(VGIC_PRI_BITS != 5);

	pri_bits = clamp(pri_bits, 1U, 8U);
	return 8 - pri_bits;
}

static unsigned int pvm_vgic_bpr1(struct kvm_vcpu *vcpu,
				  const struct vgic_vmcr *vmcr)
{
	unsigned int bpr;

	bpr = vmcr->abpr;

	return clamp(bpr, pvm_vgic_bpr_min(vcpu), 7U);
}

static u8 pvm_vgic_group_priority(struct kvm_vcpu *vcpu, u8 priority,
				  const struct vgic_vmcr *vmcr)
{
	unsigned int shift;

	shift = pvm_vgic_bpr1(vcpu, vmcr);

	return priority & (u8)(0xffU << shift);
}

static u8 pvm_vgic_running_priority(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	u32 apr = (u32)cpu_if->vgic_ap1r[0];

	if (!apr)
		return PVM_VGIC_IDLE_PRIORITY;

	return (u8)(__ffs(apr) << pvm_vgic_bpr_min(vcpu));
}

static void pvm_vgic_set_active_priority(struct kvm_vcpu *vcpu, u8 priority,
					 const struct vgic_vmcr *vmcr)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	u8 group_priority = pvm_vgic_group_priority(vcpu, priority, vmcr);
	unsigned int bit = group_priority >> pvm_vgic_bpr_min(vcpu);

	if (WARN_ON_ONCE(bit >= 32))
		return;

	cpu_if->vgic_ap1r[0] |= BIT(bit);
}

static void pvm_vgic_drop_priority(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	u32 apr = (u32)cpu_if->vgic_ap1r[0];
	unsigned int bit;

	if (!apr)
		return;

	bit = __ffs(apr);
	cpu_if->vgic_ap1r[0] &= ~BIT_ULL(bit);
}

static bool pvm_vgic_irq_pending(struct kvm_vcpu *vcpu,
				 struct vgic_irq *irq,
				 const struct vgic_vmcr *vmcr)
{
	if (!vcpu->kvm->arch.vgic.enabled || !vmcr->grpen1)
		return false;

	if (!irq->group || !irq->enabled || irq->active ||
	    !irq_is_pending(irq))
		return false;

	return vgic_target_oracle(irq) == vcpu;
}

static bool pvm_vgic_irq_deliverable(struct kvm_vcpu *vcpu,
				     struct vgic_irq *irq,
				     const struct vgic_vmcr *vmcr,
				     u8 running_priority)
{
	if (!pvm_vgic_irq_pending(vcpu, irq, vmcr))
		return false;

	if (irq->priority >= vmcr->pmr)
		return false;

	return pvm_vgic_group_priority(vcpu, irq->priority, vmcr) <
	       running_priority;
}

/* Must be called with the VCPU AP-list lock held. */
static struct vgic_irq *pvm_vgic_pick_irq(struct kvm_vcpu *vcpu,
					  const struct vgic_vmcr *vmcr,
					  u8 running_priority)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq, *best = NULL;
	u8 best_priority = PVM_VGIC_IDLE_PRIORITY;
	u32 best_intid = U32_MAX;

	lockdep_assert_held(&vgic_cpu->ap_list_lock);

	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		raw_spin_lock(&irq->irq_lock);
		if (pvm_vgic_irq_deliverable(vcpu, irq, vmcr,
					     running_priority) &&
		    (irq->priority < best_priority ||
		     (irq->priority == best_priority && irq->intid < best_intid))) {
			best = irq;
			best_priority = irq->priority;
			best_intid = irq->intid;
		}
		raw_spin_unlock(&irq->irq_lock);
	}

	return best;
}

static u32 pvm_vgic_peek_hppir1(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq, *best = NULL;
	struct vgic_vmcr vmcr;
	unsigned long flags;
	u8 best_priority = PVM_VGIC_IDLE_PRIORITY;
	u32 best_intid = U32_MAX;

	vgic_v3_get_vmcr(vcpu, &vmcr);
	raw_spin_lock_irqsave(&vgic_cpu->ap_list_lock, flags);
	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		raw_spin_lock(&irq->irq_lock);
		if (pvm_vgic_irq_pending(vcpu, irq, &vmcr) &&
		    (irq->priority < best_priority ||
		     (irq->priority == best_priority &&
		      irq->intid < best_intid))) {
			best = irq;
			best_priority = irq->priority;
			best_intid = irq->intid;
		}
		raw_spin_unlock(&irq->irq_lock);
	}
	raw_spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);

	return best ? best_intid : ICC_IAR1_EL1_SPURIOUS;
}

static u32 pvm_vgic_read_iar1(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq;
	struct vgic_vmcr vmcr;
	unsigned long flags;
	u32 intid = ICC_IAR1_EL1_SPURIOUS;

	vgic_v3_get_vmcr(vcpu, &vmcr);
	raw_spin_lock_irqsave(&vgic_cpu->ap_list_lock, flags);

	/*
	 * An injector can change pending state while we scan.  Revalidate the
	 * selected interrupt under its lock before performing the acknowledge.
	 */
	irq = pvm_vgic_pick_irq(vcpu, &vmcr,
				pvm_vgic_running_priority(vcpu));
	if (irq) {
		raw_spin_lock(&irq->irq_lock);
		if (!pvm_vgic_irq_deliverable(vcpu, irq, &vmcr,
					      pvm_vgic_running_priority(vcpu)))
			goto unlock_irq;

		intid = irq->intid;
		if (irq->config == VGIC_CONFIG_EDGE ||
		    irq->intid >= VGIC_MIN_LPI)
			irq->pending_latch = false;
		/* Mapped level IRQ inputs report rising edges, not line levels. */
		if (vgic_irq_is_mapped_level(irq))
			irq->line_level = false;
		/* LPIs have no architectural active state. */
		if (irq->intid < VGIC_MIN_LPI)
			irq->active = true;
		pvm_vgic_set_active_priority(vcpu, irq->priority, &vmcr);
unlock_irq:
		raw_spin_unlock(&irq->irq_lock);
	}

	raw_spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);
	return intid;
}

static void pvm_vgic_deactivate(struct kvm_vcpu *vcpu, u32 intid)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_irq *irq;
	unsigned long flags;
	bool notify = false;

	/* LPIs do not have an architectural active state. */
	if (intid >= VGIC_MIN_LPI)
		return;

	raw_spin_lock_irqsave(&vgic_cpu->ap_list_lock, flags);
	list_for_each_entry(irq, &vgic_cpu->ap_list_head, ap_list) {
		if (irq->intid != intid)
			continue;

		raw_spin_lock(&irq->irq_lock);
		if (!irq->active) {
			raw_spin_unlock(&irq->irq_lock);
			break;
		}

		irq->active = false;
		if (irq->config == VGIC_CONFIG_LEVEL)
			irq->pending_latch = false;

		/* No LR.HW is available to deactivate the physical interrupt. */
		if (irq->hw && !vgic_irq_needs_resampling(irq))
			vgic_irq_set_phys_active(irq, false);

		vgic_irq_handle_resampling(irq, true, irq_is_pending(irq));
		notify = irq->config == VGIC_CONFIG_LEVEL &&
			 vgic_valid_spi(vcpu->kvm, intid);

		if (!irq_is_pending(irq)) {
			/* Only LPIs carry references; they return before this path. */
			list_del_init(&irq->ap_list);
			irq->vcpu = NULL;
		}
		raw_spin_unlock(&irq->irq_lock);
		break;
	}
	raw_spin_unlock_irqrestore(&vgic_cpu->ap_list_lock, flags);

	if (notify)
		kvm_notify_acked_irq(vcpu->kvm, 0, intid - VGIC_NR_PRIVATE_IRQS);
}

static void pvm_vgic_write_eoir1(struct kvm_vcpu *vcpu, u32 intid)
{
	struct vgic_vmcr vmcr;
	unsigned long flags;

	/* Special INTIDs written to EOIR are ignored. */
	if (intid > VGIC_MAX_SPI && intid < VGIC_MIN_LPI)
		return;

	vgic_v3_get_vmcr(vcpu, &vmcr);

	/*
	 * Drop the acknowledged priority recorded in APR, independently of
	 * the IRQ's current configured priority. Out-of-order EOIR writes
	 * are architecturally UNPREDICTABLE; no INTID stack is maintained.
	 */
	raw_spin_lock_irqsave(&vcpu->arch.vgic_cpu.ap_list_lock, flags);
	pvm_vgic_drop_priority(vcpu);
	raw_spin_unlock_irqrestore(&vcpu->arch.vgic_cpu.ap_list_lock, flags);

	/* EOImode 0 combines priority drop and deactivate for non-LPIs. */
	if (!vmcr.eoim && intid < VGIC_MIN_LPI)
		pvm_vgic_deactivate(vcpu, intid);
}

static void pvm_vgic_write_dir(struct kvm_vcpu *vcpu, u32 intid)
{
	struct vgic_vmcr vmcr;

	vgic_v3_get_vmcr(vcpu, &vmcr);
	if (!vmcr.eoim || intid >= VGIC_MIN_LPI)
		return;

	pvm_vgic_deactivate(vcpu, intid);
}

static u64 pvm_vgic_read_ctlr(struct kvm_vcpu *vcpu,
			      const struct vgic_vmcr *vmcr)
{
	unsigned int pri_bits;
	u64 val;

	pri_bits = clamp(vcpu->arch.vgic_cpu.num_pri_bits, 1U, 8U);
	val = (u64)(pri_bits - 1) <<
	      ICC_CTLR_EL1_PRI_BITS_SHIFT;
	/* ICC_CTLR_EL1.IDbits encodes only the 16-bit/24-bit choices. */
	val |= (u64)min(vcpu->arch.vgic_cpu.num_id_bits, 1U) <<
	       ICC_CTLR_EL1_ID_BITS_SHIFT;
	val |= (u64)vmcr->eoim << ICC_CTLR_EL1_EOImode_SHIFT;
	return val;
}

bool kvm_pvm_vgic_cpuif_access(struct kvm_vcpu *vcpu, u32 sysreg,
			       bool is_write, u64 *val)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	struct vgic_vmcr vmcr;
	unsigned int bpr_min;

	if (!kvm_has_gicv3(vcpu->kvm))
		return false;

	vgic_v3_get_vmcr(vcpu, &vmcr);
	bpr_min = pvm_vgic_bpr_min(vcpu);

	switch (sysreg) {
	case SYS_ICC_IAR0_EL1:
	case SYS_ICC_HPPIR0_EL1:
		if (!is_write)
			*val = ICC_IAR1_EL1_SPURIOUS;
		return !is_write;
	case SYS_ICC_EOIR0_EL1:
		return is_write;
	case SYS_ICC_IAR1_EL1:
		if (!is_write)
			*val = pvm_vgic_read_iar1(vcpu);
		return !is_write;
	case SYS_ICC_HPPIR1_EL1:
		if (!is_write)
			*val = pvm_vgic_peek_hppir1(vcpu);
		return !is_write;
	case SYS_ICC_EOIR1_EL1:
		if (is_write)
			pvm_vgic_write_eoir1(vcpu, *val & PVM_VGIC_INTID_MASK);
		return is_write;
	case SYS_ICC_DIR_EL1:
		if (is_write)
			pvm_vgic_write_dir(vcpu, *val & PVM_VGIC_INTID_MASK);
		return is_write;
	case SYS_ICC_PMR_EL1:
		if (is_write) {
			vmcr.pmr = (u8)*val & (u8)(0xffU << bpr_min);
			vgic_v3_set_vmcr(vcpu, &vmcr);
		} else {
			*val = vmcr.pmr;
		}
		return true;
	case SYS_ICC_BPR0_EL1:
		/* Group 0 is outside the supported guest configuration. */
		if (!is_write)
			*val = 0;
		return true;
	case SYS_ICC_BPR1_EL1:
		if (is_write) {
			vmcr.abpr = clamp_t(u32, *val & ICC_BPR1_EL1_MASK,
					    bpr_min, 7);
			vgic_v3_set_vmcr(vcpu, &vmcr);
		} else {
			*val = pvm_vgic_bpr1(vcpu, &vmcr);
		}
		return true;
	case SYS_ICC_CTLR_EL1:
		if (is_write) {
			/* CBPR is RAZ/WI: Group 1 always uses BPR1. */
			vmcr.cbpr = 0;
			vmcr.eoim = !!(*val & ICC_CTLR_EL1_EOImode_MASK);
			vgic_v3_set_vmcr(vcpu, &vmcr);
		} else {
			*val = pvm_vgic_read_ctlr(vcpu, &vmcr);
		}
		return true;
	case SYS_ICC_IGRPEN0_EL1:
		/* Group 0 is outside the supported guest configuration. */
		if (!is_write)
			*val = 0;
		return true;
	case SYS_ICC_IGRPEN1_EL1:
		if (is_write) {
			vmcr.grpen1 = *val & 1;
			vgic_v3_set_vmcr(vcpu, &vmcr);
		} else {
			*val = vmcr.grpen1;
		}
		return true;
	case SYS_ICC_RPR_EL1:
		if (!is_write)
			*val = pvm_vgic_running_priority(vcpu);
		return !is_write;
	case SYS_ICC_SRE_EL1:
		if (!is_write)
			*val = cpu_if->vgic_sre;
		/* GICv3-only mode exposes SRE/DIB/DFB as RAO/WI. */
		return true;
	default:
		return false;
	}
}
