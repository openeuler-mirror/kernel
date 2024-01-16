// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2020-2022 Loongson Technology Corporation Limited
 */
#include <linux/version.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include "kvm_compat.h"

extern int  _kvm_set_spte_hva(struct kvm *kvm, unsigned long hva, pte_t pte);


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
	kvm_flush_remote_tlbs(kvm);
#endif
}
