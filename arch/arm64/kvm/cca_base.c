// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2025. Huawei Technologies Co., Ltd. All rights reserved.
 */
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>

#include <asm/cacheflush.h>
#include <asm/set_memory.h>
#include <asm/cca_base.h>

static int cca_cvm_type;
static struct cca_operations *g_cca_operations[CCA_CVM_MAX];

/* please use 'cca_cvm_type=$type' to enable cca cvm feature */
static int __init setup_cca_cvm_type(char *str)
{
	int ret;
	unsigned int val;

	if (!str)
		return 0;

	ret = kstrtouint(str, 10, &val);
	if (ret) {
		pr_warn("Unable to parse cca cvm_type.\n");
	} else {
		if (val >= ARMCCA_CVM && val < CCA_CVM_MAX)
			cca_cvm_type = val;
	}
	return ret;
}
early_param("cca_cvm_type", setup_cca_cvm_type);

int __init cca_operations_register(enum cca_cvm_type type, struct cca_operations *ops)
{
	if (type >= CCA_CVM_MAX)
		return -EINVAL;

	g_cca_operations[type] = ops;
	return 0;
}

int kvm_get_cvm_type(void)
{
	return cca_cvm_type;
}

void set_cca_cvm_type(int type)
{
	cca_cvm_type = type;
}
EXPORT_SYMBOL_GPL(set_cca_cvm_type);

/* Fetch the active CCA backend ops; NULL if no backend registered for cca_cvm_type. */
static struct cca_operations *cca_ops(void)
{
	if (cca_cvm_type < ARMCCA_CVM || cca_cvm_type >= CCA_CVM_MAX)
		return NULL;
	return READ_ONCE(g_cca_operations[cca_cvm_type]);
}

int kvm_realm_enable_cap(struct kvm *kvm, struct kvm_enable_cap *cap)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->enable_cap)
		return -EINVAL;
	return ops->enable_cap(kvm, cap);
}

int kvm_init_realm_vm(struct kvm *kvm)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->init_realm_vm)
		return 0;
	return ops->init_realm_vm(kvm);
}

int kvm_rec_enter(struct kvm_vcpu *vcpu)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->realm_vm_enter)
		return 0;
	return ops->realm_vm_enter(vcpu);
}

int kvm_rec_pre_enter(struct kvm_vcpu *vcpu)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->realm_vm_pre_enter)
		return 1;
	return ops->realm_vm_pre_enter(vcpu);
}

int handle_rec_exit(struct kvm_vcpu *vcpu, int rec_run_ret)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->realm_vm_exit)
		return 0;
	return ops->realm_vm_exit(vcpu, rec_run_ret);
}

void kvm_destroy_realm(struct kvm *kvm)
{
	struct cca_operations *ops = cca_ops();

	if (ops && ops->destroy_vm)
		ops->destroy_vm(kvm);
}

int kvm_create_rec(struct kvm_vcpu *vcpu)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->create_vcpu)
		return 0;
	return ops->create_vcpu(vcpu);
}

void kvm_destroy_rec(struct kvm_vcpu *vcpu)
{
	struct cca_operations *ops = cca_ops();

	if (ops && ops->destroy_vcpu)
		ops->destroy_vcpu(vcpu);
}

void kvm_init_rme(void)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->init_sel2_hypervisor)
		return;
	ops->init_sel2_hypervisor();
}

int realm_psci_complete(struct kvm_vcpu *calling, struct kvm_vcpu *target, unsigned long status)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->psci_complete)
		return 0;
	return ops->psci_complete(calling, target, status);
}

u32 kvm_realm_vgic_nr_lr(void)
{
	struct cca_operations *ops = cca_ops();

	if (!ops || !ops->vgic_nr_lr)
		return 0;
	return ops->vgic_nr_lr();
}
