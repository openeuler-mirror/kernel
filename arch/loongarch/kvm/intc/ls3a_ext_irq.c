// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/random.h>
#include "kvmcpu.h"
#include "kvm_compat.h"
#include "ls3a_ipi.h"
#include "ls7a_irq.h"
#include "ls3a_ext_irq.h"

#define ls3a_ext_irq_lock(s, flags)	spin_lock_irqsave(&s->lock, flags)
#define ls3a_ext_irq_unlock(s, flags)	spin_unlock_irqrestore(&s->lock, flags)

extern int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
			     struct kvm_loongarch_interrupt *irq);
void ext_deactive_core_isr(struct kvm *kvm, int irq_num, int vcpu_id)
{
	int ipnum;
	unsigned long found1;
	struct kvm_loongarch_interrupt irq;
	struct ls3a_kvm_extirq *s = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *state = &(s->ls3a_ext_irq);

	ipnum = state->ext_sw_ipmap[irq_num];

	bitmap_clear((void *)state->ext_isr.reg_u8, irq_num, 1);
	bitmap_clear((void *)state->ext_core_isr.reg_u8[vcpu_id], irq_num, 1);

	bitmap_clear((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], irq_num, 1);
	found1 = find_next_bit((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], EXTIOI_IRQS, 0);
	kvm_debug("vcpu_id %d irqnum %d found:0x%lx ipnum %d down\n", vcpu_id, irq_num, found1, ipnum);
	if (found1 == EXTIOI_IRQS) {
		irq.cpu = vcpu_id;
		irq.irq = -(ipnum + 2);		/* IP2~IP5 */
		if (likely(kvm->vcpus[vcpu_id]))
			kvm_vcpu_ioctl_interrupt(kvm->vcpus[vcpu_id], &irq);
		kvm->stat.trigger_ls3a_ext_irq++;
	}
}

/**
 * ext_irq_update_core()
 * @kvm: KVM structure pointer
 * @irq_num: 0~256 ext irq num
 * @level: 0~1 High and low level
 *
 * Route the status of the extended interrupt to the host CPU core.
 *
 */
void ext_irq_update_core(struct kvm *kvm, int irq_num, int level)
{
	int nrcpus, ipnum, vcpu_id;
	unsigned long found1;
	struct kvm_loongarch_interrupt irq;
	struct ls3a_kvm_extirq *s = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *state = &(s->ls3a_ext_irq);

	nrcpus = atomic_read(&kvm->online_vcpus);
	vcpu_id = state->ext_sw_coremap[irq_num];
	ipnum = state->ext_sw_ipmap[irq_num];

	if (vcpu_id > (nrcpus - 1)) {
		vcpu_id = 0;
	}

	if (level == 1) {
		if (test_bit(irq_num, (void *)state->ext_en.reg_u8) == false) {
			return;
		}
		if (test_bit(irq_num, (void *)state->ext_isr.reg_u8) == false) {
			return;
		}
		bitmap_set((void *)state->ext_core_isr.reg_u8[vcpu_id], irq_num, 1);

		found1 = find_next_bit((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], EXTIOI_IRQS, 0);
		bitmap_set((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], irq_num, 1);
		kvm_debug("%s:%d  --- vcpu_id %d irqnum %d found1 0x%lx ipnum %d\n",
					__FUNCTION__, __LINE__, vcpu_id, irq_num, found1, ipnum);
		if (found1 == EXTIOI_IRQS) {
			irq.cpu = vcpu_id;
			irq.irq = ipnum + 2;	/* IP2~IP5 */
			kvm_debug("%s:%d --- vcpu_id %d ipnum %d raise\n",
					__FUNCTION__, __LINE__, vcpu_id, ipnum);
			if (likely(kvm->vcpus[vcpu_id]))
				kvm_vcpu_ioctl_interrupt(kvm->vcpus[vcpu_id], &irq);
			kvm->stat.trigger_ls3a_ext_irq++;
		}
	} else {
		bitmap_clear((void *)state->ext_isr.reg_u8, irq_num, 1);
		bitmap_clear((void *)state->ext_core_isr.reg_u8[vcpu_id], irq_num, 1);

		bitmap_clear((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], irq_num, 1);
		found1 = find_next_bit((void *)state->ext_sw_ipisr[vcpu_id][ipnum + 2], EXTIOI_IRQS, 0);
		if (found1 == EXTIOI_IRQS) {
			irq.cpu = vcpu_id;
			irq.irq = -(ipnum + 2);		/* IP2~IP5 */
			if (likely(kvm->vcpus[vcpu_id]))
				kvm_vcpu_ioctl_interrupt(kvm->vcpus[vcpu_id], &irq);
			kvm->stat.trigger_ls3a_ext_irq++;
		}

	}
}

void msi_irq_handler(struct kvm *kvm, int irq, int level)
{
	unsigned long flags;
	struct ls3a_kvm_extirq *s = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *state = &(s->ls3a_ext_irq);

	kvm_debug("ext_irq_handler:irq = %d,level = %d\n", irq, level);

	ls3a_ext_irq_lock(s, flags);
	if (level == 1) {
		if (test_bit(irq, (void *)&state->ext_isr))
			goto out;
		__set_bit(irq, (void *)&state->ext_isr);
	} else {
		if (!test_bit(irq, (void *)&state->ext_isr))
			goto out;
		__clear_bit(irq, (void *)&state->ext_isr);
	}

	ext_irq_update_core(kvm, irq, level);
out:
	ls3a_ext_irq_unlock(s, flags);
}

static int ls3a_ext_intctl_readb(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, void *val)
{
	uint64_t offset, reg_count;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	int vcpu_id;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);

	offset = addr & 0xfffff;

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START);
		*(uint8_t *)val = state->ext_en.reg_u8[reg_count];
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START);
		*(uint8_t *)val = state->bounce.reg_u8[reg_count];
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		reg_count = (offset - EXTIOI_ISR_START);
		*(uint8_t *)val = state->ext_isr.reg_u8[reg_count];
	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		/* percpu(32 bytes) coreisr reg_count is 0~31 */
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = offset & 0xff;
		*(uint8_t *)val = state->ext_core_isr.reg_u8[vcpu_id][reg_count];
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		reg_count = (offset - EXTIOI_IPMAP_START);
		*(uint8_t *)val = state->ip_map.reg_u8[reg_count];
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		reg_count = (offset - EXTIOI_COREMAP_START);
		*(uint8_t *)val = state->core_map.reg_u8[reg_count];
	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START);
		*(uint8_t *)val = state->node_type.reg_u8[reg_count];
	}
	kvm_debug("%s: addr=0x%llx,val=0x%x\n",
				__FUNCTION__, addr, *(uint8_t *)val);
	return 0;
}

static int ls3a_ext_intctl_readw(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, void *val)
{
	uint64_t offset, reg_count;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	int vcpu_id;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);

	offset = addr & 0xfffff;

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START) / 4;
		*(uint32_t *)val = state->ext_en.reg_u32[reg_count];
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START) / 4;
		*(uint32_t *)val = state->bounce.reg_u32[reg_count];
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		reg_count = (offset - EXTIOI_ISR_START) / 4;
		*(uint32_t *)val = state->ext_isr.reg_u32[reg_count];
	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		/* percpu(32 bytes) coreisr reg_count is 0~7*/
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = (offset & 0xff) / 4;
		*(uint32_t *)val = state->ext_core_isr.reg_u32[vcpu_id][reg_count];
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		reg_count = (offset - EXTIOI_IPMAP_START) / 4;
		*(uint32_t *)val = state->ip_map.reg_u32[reg_count];
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		reg_count = (offset - EXTIOI_COREMAP_START) / 4;
		*(uint32_t *)val = state->core_map.reg_u32[reg_count];
	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START) / 4;
		*(uint32_t *)val = state->node_type.reg_u32[reg_count];
	}
	kvm_debug("%s: addr=0x%llx,val=0x%x\n",
				__FUNCTION__, addr, *(uint32_t *)val);

	return 0;
}

static int ls3a_ext_intctl_readl(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, void *val)
{
	uint64_t offset, reg_count;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	int vcpu_id;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);

	offset = addr & 0xfffff;

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START) / 8;
		*(uint64_t *)val = state->ext_en.reg_u64[reg_count];
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START) / 8;
		*(uint64_t *)val = state->bounce.reg_u64[reg_count];
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		reg_count = (offset - EXTIOI_ISR_START) / 8;
		*(uint64_t *)val = state->ext_isr.reg_u64[reg_count];
	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		/* percpu(32 bytes) coreisr reg_count is 0~3*/
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = (offset & 0xff) / 8;

		*(uint64_t *)val = state->ext_core_isr.reg_u64[vcpu_id][reg_count];
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		*(uint64_t *)val = state->ip_map.reg_u64;
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		reg_count = (offset - EXTIOI_COREMAP_START) / 8;
		*(uint64_t *)val = state->core_map.reg_u64[reg_count];
	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START) / 8;
		*(uint64_t *)val = state->node_type.reg_u64[reg_count];
	}
	kvm_debug("%s: addr=0x%llx,val=0x%llx\n",
					__FUNCTION__, addr, *(uint64_t *)val);
	return 0;
}
/**
 * ls3a_ext_intctl_read()
 * @kvm: KVM structure pointer
 * @addr: Register address
 * @size: The width of the register to be read.
 * @val: The pointer to the read result.
 *
 * Analog extended interrupt related register read.
 *
 */
static int ls3a_ext_intctl_read(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, int size, void *val)
{
	struct ls3a_kvm_extirq *s = NULL;
	unsigned long flags;
	uint64_t offset;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	offset = addr & 0xfffff;
	if (offset & (size - 1)) {
		printk("%s:unaligned address access %llx size %d\n",
			__FUNCTION__, addr, size);
		return 0;
	}
	addr = (addr & 0xfffff) - EXTIOI_ADDR_OFF;
	ls3a_ext_irq_lock(s, flags);

	switch (size) {
	case 1:
		ls3a_ext_intctl_readb(vcpu, dev, addr, val);
		break;
	case 4:
		ls3a_ext_intctl_readw(vcpu, dev, addr, val);
		break;
	case 8:
		ls3a_ext_intctl_readl(vcpu, dev, addr, val);
		break;
	default:
		WARN_ONCE(1, "%s: Abnormal address access:addr 0x%llx, size %d\n",
						__FUNCTION__, addr, size);
	}
	ls3a_ext_irq_unlock(s, flags);
	kvm_debug("%s(%d):address access %llx size %d\n",
					__FUNCTION__, __LINE__, offset, size);

	return 0;
}

static int ls3a_ext_intctl_writeb(struct kvm_vcpu *vcpu,
			 struct kvm_io_device *dev,
			 gpa_t addr, const void *__val)
{
	uint64_t offset, reg_count;
	uint8_t val_data_u8, old_data_u8;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	struct kvm *kvm = NULL;
	int  mask, level, i, irqnum, ipnum;
	int vcpu_id;

	unsigned long val = *(unsigned long *)__val;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);
	kvm = s->kvm;

	offset = addr & 0xfffff;
	val_data_u8 = val & 0xffUL;

	kvm_debug("%s: addr=0x%llx,val=0x%lx\n", __FUNCTION__, addr, val);

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START);
		old_data_u8 = state->ext_en.reg_u8[reg_count];
		if (old_data_u8 != val_data_u8) {
			state->ext_en.reg_u8[reg_count] = val_data_u8;
			old_data_u8 = old_data_u8 ^ val_data_u8;
			mask = 0x1;
			for (i = 0; i < 8; i++) {
				if (old_data_u8 & mask) {
					level = !!(val_data_u8 & (0x1 << i));
					if (level)
						ext_irq_update_core(kvm, i + reg_count * 8, level);
				}
				mask = mask << 1;
			}
		}
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START);
		state->bounce.reg_u8[reg_count] = val_data_u8;
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		/*can not be writen*/
		reg_count = (offset - EXTIOI_ISR_START) & 0x1f;
		old_data_u8 = state->ext_isr.reg_u8[reg_count];
		state->ext_isr.reg_u8[reg_count] = old_data_u8 & (~val_data_u8);

		mask = 0x1;
		for (i = 0; i < 8; i++) {
			if ((old_data_u8 & mask) && (val_data_u8 & mask)) {
				ext_irq_update_core(kvm, i + reg_count * 8, 0);
			}
			mask = mask << 1;
		}

	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		int bits;
		/* percpu(32 bytes) coreisr reg_count is 0~31 */
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = offset & 0xff;

		state->ext_core_isr.reg_u8[vcpu_id][reg_count] &= ~val_data_u8;

		bits = sizeof(val_data_u8) * 8;
		i = find_first_bit((void *)&val_data_u8, bits);
		while (i < bits) {
			ext_deactive_core_isr(kvm, i + reg_count * bits, vcpu_id);
			bitmap_clear((void *)&val_data_u8, i, 1);
			i = find_first_bit((void *)&val_data_u8, bits);
		}
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		/*drop arch.core_ip_mask use state->ip_map*/
		reg_count = (offset - EXTIOI_IPMAP_START);
		state->ip_map.reg_u8[reg_count] = val_data_u8;

		ipnum = 0;

		for (i = 0; i < 4; i++) {
			if (val_data_u8 & (0x1 << i)) {
				ipnum = i;
				break;
			}
		}

		if (val_data_u8) {
			for (i = 0; i < 32; i++) {
				irqnum = reg_count * 32 + i;
				state->ext_sw_ipmap[irqnum] = ipnum;
			}
		} else {
			for (i = 0; i < 32; i++) {
				irqnum = reg_count * 32 + i;
				state->ext_sw_ipmap[irqnum] = 0;
			}
		}
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		reg_count = (offset - EXTIOI_COREMAP_START);
		state->core_map.reg_u8[reg_count] = val_data_u8;
		state->ext_sw_coremap[reg_count] = val_data_u8;
	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START);
		state->node_type.reg_u8[reg_count] = val_data_u8;
	} else {
		WARN_ONCE(1, "%s: Abnormal address access:addr 0x%llx\n",
							__FUNCTION__, addr);
	}

	return 0;
}

static int ls3a_ext_intctl_writew(struct kvm_vcpu *vcpu,
			 struct kvm_io_device *dev,
			 gpa_t addr, const void *__val)
{
	uint64_t offset, reg_count;
	uint32_t val_data_u32, old_data_u32, mask;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	struct kvm *kvm = NULL;
	uint8_t tmp_data_u8;
	int i, level, vcpu_id;
	unsigned long val;

	val = *(unsigned long *)__val;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);
	kvm = s->kvm;

	offset = addr & 0xfffff;
	val_data_u32 = val & 0xffffffffUL;

	kvm_debug("%s: addr=0x%llx,val=0x%lx\n", __FUNCTION__, addr, val);

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START) / 4;
		old_data_u32 = state->ext_en.reg_u32[reg_count];
		if (old_data_u32 != val_data_u32) {
			state->ext_en.reg_u32[reg_count] = val_data_u32;
			old_data_u32 = old_data_u32 ^ val_data_u32;

			mask = 0x1;
			for (i = 0; i < 8 * sizeof(old_data_u32); i++) {
				if (old_data_u32 & mask) {
					level = !!(val_data_u32 & (0x1 << i));
					if (level)
						ext_irq_update_core(kvm, i + reg_count * 32, level);
				}
				mask = mask << 1;
			}
		}
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START) / 4;
		state->bounce.reg_u32[reg_count] = val_data_u32;
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		/*can not be writen*/
		reg_count = (offset - EXTIOI_ISR_START) / 4;
		old_data_u32 = state->ext_isr.reg_u32[reg_count];
		state->ext_isr.reg_u32[reg_count] = old_data_u32 & (~val_data_u32);

		mask = 0x1;
		for (i = 0; i < 8 * sizeof(old_data_u32); i++) {
			if ((old_data_u32 & mask) && (val_data_u32 & mask)) {
				ext_irq_update_core(kvm, i + reg_count * 32, 0);
			}
			mask = mask << 1;
		}
	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		int bits;
		/* percpu(32 bytes) coreisr reg_count is 0~7*/
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = (offset & 0xff) / 4;

		/*ext_core_ioisr*/
		state->ext_core_isr.reg_u32[vcpu_id][reg_count] &= ~val_data_u32;

		bits = sizeof(val_data_u32) * 8;
		i = find_first_bit((void *)&val_data_u32, bits);
		while (i < bits) {
			ext_deactive_core_isr(kvm, i + reg_count * bits, vcpu_id);
			bitmap_clear((void *)&val_data_u32, i, 1);
			i = find_first_bit((void *)&val_data_u32, bits);
		}
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		tmp_data_u8 = val_data_u32 & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 8) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 1, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 16) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 2, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 24) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 3, &tmp_data_u8);
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		tmp_data_u8 = val_data_u32 & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 8) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 1, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 16) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 2, &tmp_data_u8);
		tmp_data_u8 = (val_data_u32 >> 24) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 3, &tmp_data_u8);
		kvm_debug("%s:id:%d addr=0x%llx, offset 0x%llx val 0x%x\n",
				__FUNCTION__, vcpu->vcpu_id, addr, offset, val_data_u32);

	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START) / 4;
		state->node_type.reg_u32[reg_count] = val_data_u32;
	} else {
		WARN_ONCE(1, "%s:%d Abnormal address access:addr 0x%llx\n",
							__FUNCTION__, __LINE__, addr);
	}

	return 0;
}

static int ls3a_ext_intctl_writel(struct kvm_vcpu *vcpu,
			 struct kvm_io_device *dev,
			 gpa_t addr, const void *__val)
{
	uint64_t offset, val_data_u64, old_data_u64, reg_count, mask, i;
	struct ls3a_kvm_extirq *s = NULL;
	struct kvm_ls3a_extirq_state *state = NULL;
	struct kvm *kvm = NULL;
	uint8_t tmp_data_u8;
	int level, vcpu_id;

	unsigned long val = *(unsigned long *)__val;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	state = &(s->ls3a_ext_irq);
	kvm = s->kvm;

	offset = addr & 0xfffff;
	val_data_u64 = val;

	kvm_debug("%s: addr=0x%llx,val=0x%lx\n", __FUNCTION__, addr, val);

	if ((offset >= EXTIOI_ENABLE_START) && (offset < EXTIOI_ENABLE_END)) {
		reg_count = (offset - EXTIOI_ENABLE_START) / 8;
		old_data_u64 = state->ext_en.reg_u64[reg_count];
		if (old_data_u64 != val_data_u64) {
			state->ext_en.reg_u64[reg_count] = val_data_u64;
			old_data_u64 = old_data_u64 ^ val_data_u64;

			mask = 0x1;
			for (i = 0; i < 8 * sizeof(old_data_u64); i++) {
				if (old_data_u64 & mask) {
					level = !!(val_data_u64 & (0x1 << i));
					if (level)
						ext_irq_update_core(kvm, i + reg_count * 64, level);
				}
				mask = mask << 1;
			}
		}
	} else if ((offset >= EXTIOI_BOUNCE_START) && (offset < EXTIOI_BOUNCE_END)) {
		reg_count = (offset - EXTIOI_BOUNCE_START) / 8;
		state->bounce.reg_u64[reg_count] = val_data_u64;
	} else if ((offset >= EXTIOI_ISR_START) && (offset < EXTIOI_ISR_END)) {
		/*can not be writen*/
		reg_count = (offset - EXTIOI_ISR_START) / 8;
		old_data_u64 = state->ext_isr.reg_u64[reg_count];
		state->ext_isr.reg_u64[reg_count] = old_data_u64 & (~val_data_u64);

		mask = 0x1;
		for (i = 0; i < 8 * sizeof(old_data_u64); i++) {
			if ((old_data_u64 & mask) && (val_data_u64 & mask)) {
				ext_irq_update_core(kvm, i + reg_count * 64, 0);
			}
			mask = mask << 1;
		}
	} else if ((offset >= EXTIOI_COREISR_START) && (offset < EXTIOI_COREISR_END)) {
		int bits;
		vcpu_id = (offset >> 8) & 0xff;
		reg_count = (offset & 0x1f) / 8;

		/*core_ext_ioisr*/
		state->ext_core_isr.reg_u64[vcpu_id][reg_count] &= ~val_data_u64;

		bits = sizeof(val_data_u64) * 8;
		i = find_first_bit((void *)&val_data_u64, bits);
		while (i < bits) {
			ext_deactive_core_isr(kvm, i + reg_count * bits, vcpu_id);
			bitmap_clear((void *)&val_data_u64, i, 1);
			i = find_first_bit((void *)&val_data_u64, bits);
		}
	} else if ((offset >= EXTIOI_IPMAP_START) && (offset < EXTIOI_IPMAP_END)) {
		tmp_data_u8 = val_data_u64 & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 8) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 1, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 16) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 2, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 24) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 3, &tmp_data_u8);

		tmp_data_u8 = (val_data_u64 >> 32) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 4, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 40) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 5, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 48) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 6, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 56) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 7, &tmp_data_u8);
	} else if ((offset >= EXTIOI_COREMAP_START) && (offset < EXTIOI_COREMAP_END)) {
		tmp_data_u8 = val_data_u64 & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 8) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 1, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 16) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 2, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 24) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 3, &tmp_data_u8);

		tmp_data_u8 = (val_data_u64 >> 32) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 4, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 40) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 5, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 48) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 6, &tmp_data_u8);
		tmp_data_u8 = (val_data_u64 >> 56) & 0xff;
		ls3a_ext_intctl_writeb(vcpu, dev, addr + 7, &tmp_data_u8);
	} else if ((offset >= EXTIOI_NODETYPE_START) && (offset < EXTIOI_NODETYPE_END)) {
		reg_count = (offset - EXTIOI_NODETYPE_START) / 8;
		state->node_type.reg_u64[reg_count] = val_data_u64;
	} else {
		WARN_ONCE(1, "%s:%d Abnormal address access:addr 0x%llx\n",
					__FUNCTION__, __LINE__, addr);
	}
	return 0;
}
/**
 * ls3a_ext_intctl_write()
 * @kvm: KVM structure pointer
 * @addr: Register address
 * @size: The width of the register to be writen.
 * @val: Value to be written.
 *
 * Analog extended interrupt related register write.
 *
 */
static int ls3a_ext_intctl_write(struct kvm_vcpu *vcpu,
			 struct kvm_io_device *dev,
			 gpa_t addr, int size, const void *__val)
{
	struct ls3a_kvm_extirq *s = NULL;
	unsigned long flags;
	uint64_t offset;

	s = container_of(dev, struct ls3a_kvm_extirq, device);

	offset = addr & 0xfffff;
	if (offset & (size - 1)) {
		printk("%s(%d):unaligned address access %llx size %d\n",
			__FUNCTION__, __LINE__, addr, size);
		return 0;
	}

	addr = (addr & 0xfffff) - EXTIOI_ADDR_OFF;
	ls3a_ext_irq_lock(s, flags);

	switch (size) {
	case 1:
		ls3a_ext_intctl_writeb(vcpu, dev, addr, __val);
		break;
	case 4:
		ls3a_ext_intctl_writew(vcpu, dev, addr, __val);
		break;
	case 8:
		ls3a_ext_intctl_writel(vcpu, dev, addr, __val);
		break;
	default:
		WARN_ONCE(1, "%s: Abnormal address access:addr 0x%llx,size %d\n",
						__FUNCTION__, addr, size);
	}

	ls3a_ext_irq_unlock(s, flags);

	kvm_debug("%s(%d):address access %llx size %d\n",
					__FUNCTION__, __LINE__, offset, size);
	return 0;
}

static const struct kvm_io_device_ops kvm_ls3a_ext_irq_ops = {
	.read     = ls3a_ext_intctl_read,
	.write    = ls3a_ext_intctl_write,
};

void kvm_destroy_ls3a_ext_irq(struct kvm *kvm)
{
	struct ls3a_kvm_extirq *s = kvm->arch.v_extirq;

	if (!s)
		return;
	kvm_io_bus_unregister_dev(s->kvm, KVM_MMIO_BUS, &s->device);
	kfree(s);
}
/*
 * kvm_create_ls3a_ext_irq()
 * @kvm KVM structure pointer
 * Create an extended interrupt resource instance for a virtual machine
 * Returns: Extended interrupt structure pointer
 */
int kvm_create_ls3a_ext_irq(struct kvm *kvm)
{
	struct ls3a_kvm_extirq *s;
	int  ret;

	s = kzalloc(sizeof(struct ls3a_kvm_extirq), GFP_KERNEL);
	if (!s)
		return -ENOMEM;

	memset((void *)&s->ls3a_ext_irq, 0x0, sizeof(struct kvm_ls3a_extirq_state));

	spin_lock_init(&s->lock);
	s->kvm = kvm;

	/*
	 * Initialize MMIO device
	 */
	kvm_iodevice_init(&s->device, &kvm_ls3a_ext_irq_ops);
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
					EXTIOI_REG_BASE, EXTIOI_ADDR_SIZE, &s->device);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		printk("%s dev_ls3a_ext_irq register error  ret %d\n", __FUNCTION__, ret);
		goto err_register;
	}

	kvm->arch.v_extirq = s;

	return 0;

err_register:
	kfree(s);
	return -EFAULT;
}

static int kvm_set_ext_sw_ipmap(struct kvm_ls3a_extirq_state *state)
{
	uint8_t val_data_u8;
	int   i, j, base_irq, irqnum, ipnum;

	ipnum = 0;
	for (i = 0; i < EXTIOI_IRQS_IPMAP_SIZE; i++) {
		val_data_u8 = state->ip_map.reg_u8[i];
		for (j = 0; j < 4; j++) {
			if (val_data_u8 & (0x1 << j)) {
				ipnum = j;
				break;
			}
		}
		kvm_debug("%s:%d ipnum:%d i:%d val_data_u8:0x%x\n", __FUNCTION__, __LINE__,
									ipnum, i, val_data_u8);

		if (val_data_u8) {
			for (base_irq = 0; base_irq < EXTIOI_IRQS_PER_GROUP; base_irq++) {
				irqnum = i * EXTIOI_IRQS_PER_GROUP + base_irq;
				state->ext_sw_ipmap[irqnum] = ipnum;
			}
		} else {
			for (base_irq = 0; base_irq < EXTIOI_IRQS_PER_GROUP; base_irq++) {
				irqnum = i * EXTIOI_IRQS_PER_GROUP + base_irq;
				state->ext_sw_ipmap[irqnum] = 0;
			}
		}
	}

	return 0;
}

static int kvm_set_ext_sw_coremap(struct kvm *kvm, struct kvm_ls3a_extirq_state *state)
{
	int reg_count;

	for (reg_count = 0; reg_count < EXTIOI_IRQS; reg_count++) {
		state->ext_sw_coremap[reg_count] = state->core_map.reg_u8[reg_count];

		kvm_debug("%s:%d  -- reg_count:%d vcpu %d\n",
				__FUNCTION__, __LINE__, reg_count, state->core_map.reg_u8[reg_count]);
	}

	return 0;
}

static int kvm_set_ext_sw_ipisr(struct kvm *kvm, struct kvm_ls3a_extirq_state *state)
{
	int ipnum, core, irq_num;

	for (irq_num = 0; irq_num < EXTIOI_IRQS; irq_num++) {
		core = state->ext_sw_coremap[irq_num];
		ipnum = state->ext_sw_ipmap[irq_num];

		if (test_bit(irq_num, (void *)state->ext_core_isr.reg_u8[core]) == false) {
			bitmap_clear((void *)state->ext_sw_ipisr[core][ipnum + 2], irq_num, 1);
		} else {
			bitmap_set((void *)state->ext_sw_ipisr[core][ipnum + 2], irq_num, 1);
		}

	}
	return 0;
}

int kvm_get_ls3a_extirq(struct kvm *kvm, struct kvm_loongarch_ls3a_extirq_state *state)
{
	struct ls3a_kvm_extirq *v_extirq = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *extirq_state = &(v_extirq->ls3a_ext_irq);
	unsigned long flags;
	if (!v_extirq)
		return -EINVAL;

	ls3a_ext_irq_lock(v_extirq, flags);
	memcpy(state, extirq_state,
		sizeof(struct kvm_loongarch_ls3a_extirq_state));
	ls3a_ext_irq_unlock(v_extirq, flags);
	kvm->stat.get_ls3a_ext_irq++;

	return 0;
}

int kvm_set_ls3a_extirq(struct kvm *kvm, struct kvm_loongarch_ls3a_extirq_state *state)
{
	struct ls3a_kvm_extirq *v_extirq = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *extirq_state = &(v_extirq->ls3a_ext_irq);
	unsigned long flags;
	if (!v_extirq)
		return -EINVAL;

	ls3a_ext_irq_lock(v_extirq, flags);
	memcpy(extirq_state, state,
		sizeof(struct kvm_loongarch_ls3a_extirq_state));
	kvm_set_ext_sw_ipmap(extirq_state);
	kvm_set_ext_sw_coremap(kvm, extirq_state);
	kvm_set_ext_sw_ipisr(kvm, extirq_state);

	ls3a_ext_irq_unlock(v_extirq, flags);
	kvm->stat.set_ls3a_ext_irq++;

	return 0;
}

int kvm_setup_ls3a_extirq(struct kvm *kvm)
{
	struct ls3a_kvm_extirq *v_extirq = ls3a_ext_irqchip(kvm);
	struct kvm_ls3a_extirq_state *extirq_state = &(v_extirq->ls3a_ext_irq);
	unsigned long flags;

	if (!v_extirq)
		return -EINVAL;

	ls3a_ext_irq_lock(v_extirq, flags);
	memset(extirq_state, 0,	sizeof(struct kvm_ls3a_extirq_state));
	ls3a_ext_irq_unlock(v_extirq, flags);

	return 0;
}

void kvm_dump_ls3a_extirq_state(struct seq_file *s,
		struct ls3a_kvm_extirq *irqchip)
{
	struct kvm_ls3a_extirq_state *extirq;
	int i, j = 0;
	unsigned long flags;

	seq_puts(s, "LS3A ext irqchip state:\n");

	if (!irqchip)
		return;

	extirq = &(irqchip->ls3a_ext_irq);
	ls3a_ext_irq_lock(irqchip, flags);
	seq_puts(s, "ext irq enabled");
	seq_puts(s, "\nenabled:(Not Enabled)");
	for (i = 0; i < EXTIOI_IRQS; i++) {
		if (!test_bit(i, (void *)&extirq->ext_en))
			seq_printf(s, "%d ", i);
	}
	seq_puts(s, "\nbounce:(Not bounce)");
	for (i = 0; i < EXTIOI_IRQS; i++) {
		if (!test_bit(i, (void *)&extirq->bounce))
			seq_printf(s, "%d ", i);
	}
	seq_puts(s, "\next_isr:");
	for (i = 0; i < EXTIOI_IRQS; i++) {
		if (test_bit(i, (void *)&extirq->ext_isr))
			seq_printf(s, "%d ", i);
	}

	seq_puts(s, "\ncore_isr:");
	for (i = 0; i < KVM_MAX_VCPUS && kvm_get_vcpu_by_id(irqchip->kvm, i); i++) {
		seq_printf(s, "\n\t CPU%d:", i);
		for (j = 0; j < EXTIOI_IRQS; j++) {
			if (test_bit(j, (void *)&extirq->ext_core_isr.reg_u8[i]))
				seq_printf(s, "%d ", j);
		}
	}
	seq_printf(s, "\nip_map:%llx", extirq->ip_map.reg_u64);
	seq_puts(s, "\ncore_map: (only display router to slave cpu)\n");
	for (i = 0; i < EXTIOI_IRQS_COREMAP_SIZE; i++)
		if (extirq->core_map.reg_u8[i])
			seq_printf(s, "\tirq:%d -> cpu:%d\n", i,
					extirq->core_map.reg_u8[i]);
	ls3a_ext_irq_unlock(irqchip, flags);
}
