// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */

#include <linux/debugfs.h>
#include <linux/kvm_host.h>
#include <linux/seq_file.h>
#include "kvmcpu.h"
#include "ls3a_ext_irq.h"
#include "ls7a_irq.h"

#ifdef CONFIG_DEBUG_FS
static int irqchip_state_show(struct seq_file *m, void *v)
{
	struct kvm *kvm = m->private;

	kvm_get_kvm(kvm);
	kvm_dump_ls3a_extirq_state(m, kvm->arch.v_extirq);
	kvm_dump_ls7a_ioapic_state(m, kvm->arch.v_ioapic);
	kvm_put_kvm(kvm);

	return 0;
}

static int irqchip_debug_open(struct inode *inode, struct file *file)
{
	return single_open(file, irqchip_state_show, inode->i_private);
}

static const struct file_operations irqchip_debug_fops = {
	.open       = irqchip_debug_open,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.release    = single_release,
};

void irqchip_debug_init(struct kvm *kvm)
{
	debugfs_create_file("irqchip-state", 0444, kvm->debugfs_dentry, kvm,
			    &irqchip_debug_fops);
}
#else

void irqchip_debug_init(struct kvm *kvm) {}
#endif
void irqchip_debug_destroy(struct kvm *kvm)
{
}
