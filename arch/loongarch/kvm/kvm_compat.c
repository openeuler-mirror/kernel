// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/version.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include "kvm_compat.h"

extern int  _kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);

#if (LINUX_VERSION_CODE < KERNEL_VERSION(5, 4, 0))
void kvm_arch_check_processor_compat(void *rtn)
{
	*(int *)rtn = 0;
}

void kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	_kvm_set_spte_hva(kvm, hva, pte);
	return;
}

#elif (LINUX_VERSION_CODE == KERNEL_VERSION(5, 4, 0))
int kvm_arch_check_processor_compat(void)
{
	return 0;
}

int kvm_vm_ioctl_clear_dirty_log(struct kvm *kvm, struct kvm_clear_dirty_log *log)
{
	struct kvm_memslots *slots;
	struct kvm_memory_slot *memslot;
	bool is_dirty = false;
	int r;

	mutex_lock(&kvm->slots_lock);

	r = kvm_clear_dirty_log_protect(kvm, log, &is_dirty);

	if (is_dirty) {
		slots = kvm_memslots(kvm);
		memslot = id_to_memslot(slots, log->slot);

		/* Let implementation handle TLB/GVA invalidation */
		kvm_flush_remote_tlbs(kvm);
	}

	mutex_unlock(&kvm->slots_lock);
	return r;
}

int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	return _kvm_set_spte_hva(kvm, hva, pte);
}
#else
int kvm_arch_check_processor_compat(void *opaque)
{
	return 0;
}

int kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte)
{
	return _kvm_set_spte_hva(kvm, hva, pte);
}

void kvm_arch_sync_dirty_log(struct kvm *kvm, struct kvm_memory_slot *memslot)
{

}

int kvm_arch_vcpu_precreate(struct kvm *kvm, unsigned int id)
{
	return 0;
}

void kvm_arch_flush_remote_tlbs_memslot(struct kvm *kvm,
					struct kvm_memory_slot *memslot)
{
#ifndef CONFIG_HAVE_KVM_ARCH_TLB_FLUSH_ALL
	kvm_flush_remote_tlbs (kvm);
#endif
}
#endif
