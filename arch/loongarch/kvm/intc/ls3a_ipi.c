// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include "kvmcpu.h"
#include "ls3a_ipi.h"
#include "ls7a_irq.h"
#include "ls3a_ext_irq.h"

#define ls3a_gipi_lock(s, flags)	spin_lock_irqsave(&s->lock, flags)
#define ls3a_gipi_unlock(s, flags)	spin_unlock_irqrestore(&s->lock, flags)

extern int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu,
			     struct kvm_loongarch_interrupt *irq);
int kvm_helper_send_ipi(struct kvm_vcpu *vcpu, unsigned int cpu, unsigned int action)
{
	struct kvm *kvm = vcpu->kvm;
	struct ls3a_kvm_ipi *ipi = ls3a_ipi_irqchip(kvm);
	gipiState *s = &(ipi->ls3a_gipistate);
	unsigned long flags;
	struct kvm_loongarch_interrupt irq;

	kvm->stat.pip_write_exits++;

	ls3a_gipi_lock(ipi, flags);
	if (s->core[cpu].status == 0) {
		irq.cpu = cpu;
		irq.irq = LARCH_INT_IPI;
		kvm_vcpu_ioctl_interrupt(kvm->vcpus[cpu], &irq);
	}

	s->core[cpu].status |= action;
	ls3a_gipi_unlock(ipi, flags);

	return 0;
}

static int ls3a_gipi_writel(struct ls3a_kvm_ipi *ipi, gpa_t addr,
						int len, const void *val)
{
	uint64_t data, offset;
	struct kvm_loongarch_interrupt irq;
	gipiState *s = &(ipi->ls3a_gipistate);
	uint32_t cpu, action_data;
	struct kvm *kvm;
	void *pbuf;
	int mailbox, action;

	kvm = ipi->kvm;
	cpu = (addr >> 8) & 0xff;

	data = *(uint64_t *)val;
	offset = addr & 0xFF;

	BUG_ON(offset & (len - 1));

	switch (offset) {
	case CORE0_STATUS_OFF:
		printk("CORE0_SET_OFF Can't be write\n");

		break;
	case CORE0_EN_OFF:
		s->core[cpu].en = data;

		break;
	case CORE0_IPI_SEND:
		cpu = ((data & 0xffffffff) >> 16) & 0x3ff;
		action = (data & 0x1f);
		action_data = (1 << action);

		if (s->core[cpu].status == 0) {
			irq.cpu = cpu;
			irq.irq = LARCH_INT_IPI;

			if (likely(kvm->vcpus[cpu])) {
				kvm_vcpu_ioctl_interrupt(kvm->vcpus[cpu], &irq);
			}
		}
		s->core[cpu].status |= action_data;
		break;
	case CORE0_SET_OFF:
		pr_info("CORE0_SET_OFF simulation is required\n");
		break;
	case CORE0_CLEAR_OFF:
		s->core[cpu].status &= ~data;
		if (!s->core[cpu].status) {
			irq.cpu = cpu;
			irq.irq = -LARCH_INT_IPI;
			if (likely(kvm->vcpus[cpu]))
				kvm_vcpu_ioctl_interrupt(kvm->vcpus[cpu], &irq);
			else
				kvm_err("Failed lower ipi irq target cpu:%d\n", cpu);
		}

		break;
	case CORE0_MAIL_SEND:
		cpu = ((data & 0xffffffff) >> 16) & 0x3ff;
		mailbox = ((data & 0xffffffff) >> 2) & 0x7;
		pbuf =  (void *)s->core[cpu].buf + mailbox * 4;

		*(unsigned int *)pbuf = (unsigned int)(data >> 32);
		break;
	case 0x20 ... 0x3c:
		pbuf =  (void *)s->core[cpu].buf + (offset - 0x20);
		if (len == 1)
			*(unsigned char *)pbuf = (unsigned char)data;
		else if (len == 2)
			*(unsigned short *)pbuf = (unsigned short)data;
		else if (len == 4)
			*(unsigned int *)pbuf = (unsigned int)data;
		else if (len == 8)
			*(unsigned long *)pbuf = (unsigned long)data;

		break;
	default:
		printk("ls3a_gipi_writel with unknown addr %llx \n", addr);
		break;
	}
	return 0;
}

static uint64_t ls3a_gipi_readl(struct ls3a_kvm_ipi *ipi,
				gpa_t addr, int len, void *val)
{
	uint64_t offset;
	uint64_t ret = 0;

	gipiState *s = &(ipi->ls3a_gipistate);
	uint32_t cpu;
	void *pbuf;

	cpu = (addr >> 8) & 0xff;

	offset = addr & 0xFF;

	BUG_ON(offset & (len - 1));
	switch (offset) {
	case CORE0_STATUS_OFF:
		ret = s->core[cpu].status;
		break;
	case CORE0_EN_OFF:
		ret = s->core[cpu].en;
		break;
	case CORE0_SET_OFF:
		ret = 0;
		break;
	case CORE0_CLEAR_OFF:
		ret = 0;
		break;
	case 0x20 ... 0x3c:
		pbuf =  (void *)s->core[cpu].buf + (offset - 0x20);
		if (len == 1)
			ret  = *(unsigned char *)pbuf;
		else if (len == 2)
			ret = *(unsigned short *)pbuf;
		else if (len == 4)
			ret = *(unsigned int *)pbuf;
		else if (len == 8)
			ret = *(unsigned long *)pbuf;
		break;
	default:
		printk("ls3a_gipi_readl with unknown addr %llx \n", addr);
		break;
	}

	*(uint64_t *)val = ret;

	return ret;
}

static int kvm_ls3a_ipi_write(struct kvm_vcpu *vcpu,
			      struct kvm_io_device *dev,
			      gpa_t addr, int len, const void *val)
{
	struct ls3a_kvm_ipi *ipi;
	ipi_io_device *ipi_device;
	unsigned long flags;

	ipi_device = container_of(dev, ipi_io_device, device);
	ipi = ipi_device->ipi;
	ipi->kvm->stat.pip_write_exits++;

	ls3a_gipi_lock(ipi, flags);
	ls3a_gipi_writel(ipi, addr, len, val);
	ls3a_gipi_unlock(ipi, flags);
	return 0;
}


static int kvm_ls3a_ipi_read(struct kvm_vcpu *vcpu,
			     struct kvm_io_device *dev,
			     gpa_t addr, int len, void *val)
{
	struct ls3a_kvm_ipi *ipi;
	ipi_io_device *ipi_device;
	unsigned long flags;

	ipi_device = container_of(dev, ipi_io_device, device);
	ipi = ipi_device->ipi;
	ipi->kvm->stat.pip_read_exits++;

	ls3a_gipi_lock(ipi, flags);
	ls3a_gipi_readl(ipi, addr, len, val);
	ls3a_gipi_unlock(ipi, flags);
	return 0;
}


static const struct kvm_io_device_ops kvm_ls3a_ipi_ops = {
	.read	= kvm_ls3a_ipi_read,
	.write	= kvm_ls3a_ipi_write,
};

void kvm_destroy_ls3a_ipi(struct kvm *kvm)
{
	struct kvm_io_device *device;
	struct ls3a_kvm_ipi *vipi = kvm->arch.v_gipi;

	if (!vipi)
		return;
	device = &vipi->dev_ls3a_ipi.device;
	kvm_io_bus_unregister_dev(vipi->kvm, KVM_MMIO_BUS, device);
	kfree(vipi);
}

int kvm_create_ls3a_ipi(struct kvm *kvm)
{
	struct ls3a_kvm_ipi *s;
	unsigned long addr;
	struct kvm_io_device *device;
	int ret;

	s = kzalloc(sizeof(struct ls3a_kvm_ipi), GFP_KERNEL);
	if (!s)
		return -ENOMEM;
	spin_lock_init(&s->lock);
	s->kvm = kvm;

	/*
	 * Initialize MMIO device
	 */
	device = &s->dev_ls3a_ipi.device;
	kvm_iodevice_init(device, &kvm_ls3a_ipi_ops);
	addr = SMP_MAILBOX;
	mutex_lock(&kvm->slots_lock);
	ret = kvm_io_bus_register_dev(kvm, KVM_MMIO_BUS,
			addr, KVM_IOCSR_IPI_ADDR_SIZE, device);
	mutex_unlock(&kvm->slots_lock);
	if (ret < 0) {
		kvm_err("%s Initialize MMIO dev err ret:%d\n", __func__, ret);
		goto err;
	} else {
		s->dev_ls3a_ipi.ipi = s;
	}

	kvm->arch.v_gipi = s;
	return 0;

err:
	kfree(s);
	return -EFAULT;
}

int kvm_get_ls3a_ipi(struct kvm *kvm, struct loongarch_gipiState *state)
{
	struct ls3a_kvm_ipi *ipi = ls3a_ipi_irqchip(kvm);
	gipiState *ipi_state =  &(ipi->ls3a_gipistate);
	unsigned long flags;

	ls3a_gipi_lock(ipi, flags);
	memcpy(state, ipi_state, sizeof(gipiState));
	ls3a_gipi_unlock(ipi, flags);
	return 0;
}

int kvm_set_ls3a_ipi(struct kvm *kvm, struct loongarch_gipiState *state)
{
	struct ls3a_kvm_ipi *ipi = ls3a_ipi_irqchip(kvm);
	gipiState *ipi_state =  &(ipi->ls3a_gipistate);
	unsigned long flags;

	if (!ipi)
		return -EINVAL;

	ls3a_gipi_lock(ipi, flags);
	memcpy(ipi_state, state, sizeof(gipiState));
	ls3a_gipi_unlock(ipi, flags);
	return 0;
}
