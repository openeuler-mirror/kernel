// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/kvm_host.h>
#include <linux/kobject.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sysfs.h>

#include <asm/kvm_mmu.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_pvm.h>
#include <asm/pgtable.h>

#include "mmu.h"

/*
 * Context replacement acquires the new kernel pin before releasing the
 * old one. Two contexts per vCPU cover both pins during a switch, including
 * temporary reservations held while reclaim drops mmu_lock.
 */
#define PVM_SKERN_MMUS_PER_VCPU 2

static unsigned int pvm_mmus_per_vcpu = 8;
static struct kobject *pvm_kobj;

static ssize_t mmus_per_vcpu_show(struct kobject *kobj,
				  struct kobj_attribute *attr, char *buf)
{
	return sysfs_emit(buf, "%u\n", READ_ONCE(pvm_mmus_per_vcpu));
}

static ssize_t mmus_per_vcpu_store(struct kobject *kobj,
				   struct kobj_attribute *attr,
				   const char *buf, size_t count)
{
	unsigned int factor;
	int ret;

	ret = kstrtouint(buf, 0, &factor);
	if (ret)
		return ret;
	if (factor != 2 && factor != 4 && factor != 8 && factor != 16)
		return -EINVAL;
	WRITE_ONCE(pvm_mmus_per_vcpu, factor);
	return count;
}

static struct kobj_attribute mmus_per_vcpu_attr = __ATTR_RW(mmus_per_vcpu);

int __init kvm_pvm_sysfs_init(void)
{
	struct module_kobject *mk;
	int ret;

	if (!IS_ENABLED(CONFIG_SYSFS))
		return 0;
	/* Built-in module attributes may not have created the KVM node yet. */
	mk = lookup_or_create_module_kobject(KBUILD_MODNAME);
	if (!mk)
		return -ENOMEM;
	pvm_kobj = kobject_create_and_add("pvm", &mk->kobj);
	kobject_put(&mk->kobj);
	if (!pvm_kobj)
		return -ENOMEM;
	ret = sysfs_create_file(pvm_kobj, &mmus_per_vcpu_attr.attr);
	if (ret) {
		kobject_put(pvm_kobj);
		pvm_kobj = NULL;
	}
	return ret;
}

void kvm_pvm_sysfs_exit(void)
{
	if (!pvm_kobj)
		return;
	sysfs_remove_file(pvm_kobj, &mmus_per_vcpu_attr.attr);
	kobject_put(pvm_kobj);
	pvm_kobj = NULL;
}

/* Keep host mappings usable by EL1 but inaccessible to the EL0 guest. */
static int pvm_copy_host_pgd(pgd_t *pgd)
{
	unsigned int i;

	memcpy(pgd, init_mm.pgd, PAGE_SIZE);
	for (i = 0; i < PTRS_PER_PGD - 1; i++) {
		pgdval_t entry = pgd_val(pgd[i]);

		if (!(entry & PTE_VALID))
			continue;
		/* With a 4K host granule and 48-bit VA, level 0 is a table. */
		if ((entry & P4D_TYPE_MASK) != P4D_TYPE_TABLE)
			return -EOPNOTSUPP;
		/* APTable[0] denies EL0 data; UXNTable denies EL0 execution. */
		pgd[i] = __pgd(entry | BIT_ULL(61) | P4D_TABLE_UXN);
	}
	pgd[PTRS_PER_PGD - 1] = __pgd(0);
	return 0;
}

int kvm_pvm_init_mmu(struct kvm *kvm)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	struct page *page;
	pgd_t *pgd;
	int ret;

	/* The guest window must not replace a live host mapping. */
	if (pgd_val(READ_ONCE(init_mm.pgd[PTRS_PER_PGD - 1])))
		return -EOPNOTSUPP;
	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (!page)
		return -ENOMEM;
	pgd = page_address(page);
	ret = pvm_copy_host_pgd(pgd);
	if (ret) {
		__free_page(page);
		return ret;
	}
	pvm->kern_pgd_phys = page_to_phys(page);
	pvm->kern_pgd_page = page;
	pvm->mmus_per_vcpu = READ_ONCE(pvm_mmus_per_vcpu);
	return 0;
}

u64 kvm_pvm_shadow_s1_addr(u64 va)
{
	return va & PVM_SHADOW_S1_ADDR_MASK;
}

bool kvm_pvm_is_kernel_va(u64 va)
{
	return (va & BIT_ULL(55)) ||
	       kvm_pvm_shadow_s1_addr(va) >= PVM_SHADOW_S1_KERNEL_BASE;
}

void kvm_pvm_set_kern_pgd(struct kvm_pvm_mmu *mmu, u64 pte)
{
	set_pgd(&mmu->kern_pgd[PTRS_PER_PGD - 1], __pgd(pte));
}

static void pvm_free_mmu(struct kvm_pvm_mmu *mmu)
{
	if (!mmu)
		return;
	WARN_ON_ONCE(mmu->active);
	if (mmu->kern_pgd_page)
		__free_page(mmu->kern_pgd_page);
	kvm_free_stage2_pgd(&mmu->mmu);
	kfree(mmu);
}

static struct kvm_pvm_mmu *pvm_alloc_mmu(struct kvm *kvm, bool kernel)
{
	struct kvm_pvm_mmu *mmu;
	int ret;

	mmu = kzalloc(sizeof(*mmu), GFP_KERNEL_ACCOUNT);
	if (!mmu)
		return ERR_PTR(-ENOMEM);
	ret = kvm_init_shadow_mmu(kvm, &mmu->mmu);
	if (ret) {
		kfree(mmu);
		return ERR_PTR(ret);
	}
	if (kernel) {
		mmu->kern_pgd_page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
		if (!mmu->kern_pgd_page) {
			pvm_free_mmu(mmu);
			return ERR_PTR(-ENOMEM);
		}
		mmu->kern_pgd = page_address(mmu->kern_pgd_page);
		mmu->kern_pgd_phys = page_to_phys(mmu->kern_pgd_page);
		ret = pvm_copy_host_pgd(mmu->kern_pgd);
		if (ret) {
			pvm_free_mmu(mmu);
			return ERR_PTR(ret);
		}
	}
	return mmu;
}

/* Grow one pool, keeping the existing contexts at their current indices. */
static int pvm_grow_pool(struct kvm *kvm, struct kvm_pvm_mmu ***pool,
			 size_t *size, size_t new_size, bool kernel)
{
	struct kvm_pvm_mmu **old = *pool;
	struct kvm_pvm_mmu **new;
	size_t old_size = *size;
	size_t i;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	new = kvcalloc(new_size, sizeof(*new), GFP_KERNEL_ACCOUNT);
	if (!new)
		return -ENOMEM;

	if (old_size)
		memcpy(new, old, size_mul(old_size, sizeof(*old)));

	for (i = old_size; i < new_size; i++) {
		new[i] = pvm_alloc_mmu(kvm, kernel);
		if (IS_ERR(new[i])) {
			ret = PTR_ERR(new[i]);
			goto err_free_new;
		}
	}

	write_lock(&kvm->mmu_lock);
	*pool = new;
	*size = new_size;
	write_unlock(&kvm->mmu_lock);
	kvfree(old);
	return 0;

err_free_new:
	while (i-- > old_size)
		pvm_free_mmu(new[i]);
	kvfree(new);
	return ret;
}

/*
 * KVM_ARM_VCPU_INIT runs after KVM_CREATE_VCPU has accounted the vCPU in
 * online_vcpus. Size the shared pool for all vCPUs created so far, whether
 * userspace initializes them one at a time or after creating the full set.
 */
int kvm_pvm_init_vcpu_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t vcpus = atomic_read(&kvm->online_vcpus);
	size_t user_size = vcpus * pvm->mmus_per_vcpu;
	size_t kern_size;
	int ret;

	lockdep_assert_held(&kvm->arch.config_lock);

	if (user_size > pvm->suser_mmus_size) {
		ret = pvm_grow_pool(kvm, &pvm->suser_mmus,
				    &pvm->suser_mmus_size, user_size, false);
		if (ret)
			return ret;
	}

	/*
	 * The VM-wide pool must cover each vCPU holding both its old kernel
	 * context and a new context during replacement.
	 */
	kern_size = vcpus * PVM_SKERN_MMUS_PER_VCPU;
	if (kern_size > pvm->skern_mmus_size) {
		ret = pvm_grow_pool(kvm, &pvm->skern_mmus, &pvm->skern_mmus_size,
				    kern_size, true);
		if (ret)
			return ret;
	}

	return 0;
}

void kvm_pvm_destroy_mmu(struct kvm *kvm)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t i;

	for (i = 0; i < pvm->suser_mmus_size; i++)
		pvm_free_mmu(pvm->suser_mmus[i]);
	for (i = 0; i < pvm->skern_mmus_size; i++)
		pvm_free_mmu(pvm->skern_mmus[i]);

	kvfree(pvm->suser_mmus);
	kvfree(pvm->skern_mmus);
	pvm->suser_mmus = NULL;
	pvm->skern_mmus = NULL;
	pvm->suser_mmus_size = 0;
	pvm->skern_mmus_size = 0;
	pvm->suser_mmus_next = 0;
	pvm->skern_mmus_next = 0;
	if (pvm->kern_pgd_page) {
		__free_page(pvm->kern_pgd_page);
		pvm->kern_pgd_phys = 0;
		pvm->kern_pgd_page = NULL;
	}
}

bool kvm_pvm_vcpu_mmu_enabled(struct kvm_vcpu *vcpu)
{
	return ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1) & SCTLR_ELx_M;
}

static u16 pvm_guest_asid(struct kvm_vcpu *vcpu, u64 tcr)
{
	u64 ttbr = ctxt_sys_reg(&vcpu->arch.ctxt,
			       (tcr & TCR_A1) ? TTBR1_EL1 : TTBR0_EL1);
	u16 asid = FIELD_GET(TTBR_ASID_MASK, ttbr);

	return (tcr & TCR_ASID16) ? asid : asid & 0xff;
}

static void pvm_put_mmu(struct kvm_pvm_mmu *mmu)
{
	if (WARN_ON_ONCE(!mmu->active))
		return;
	mmu->active--;
}

static void pvm_unmap_mmu(struct kvm_pvm_mmu *mmu, bool may_block)
{
	/* A copied host root borrows only this context's guest subtree. */
	if (mmu->kern_pgd) {
		kvm_pvm_set_kern_pgd(mmu, 0);
		kvm_call_hyp(__kvm_tlb_flush_vmid, &mmu->mmu);
		unmap_stage2_range(&mmu->mmu, PVM_SHADOW_S1_KERNEL_BASE,
				   BIT_ULL(PVM_GKERNEL_VA_BITS), may_block);
	} else {
		unmap_stage2_range(&mmu->mmu, 0,
				   BIT_ULL(mmu->mmu.pgt->ia_bits), may_block);
	}
}

static bool pvm_key_matches(struct kvm_pvm_mmu *mmu, bool kernel, u64 tcr,
			    u64 sctlr, u64 mair, u64 ttbr0, u64 ttbr1, u16 asid)
{
	if (mmu->tcr != tcr || mmu->sctlr != sctlr || mmu->mair != mair)
		return false;

	return kernel ? mmu->ttbr1 == ttbr1 :
			mmu->ttbr0 == ttbr0 && mmu->asid == asid;
}

/*
 * Serve the requested translation regime, recycling a context when the pool
 * is full.
 *
 * The pools are bounded rather than growing with every translation regime.
 * Only an unpinned context may be reclaimed: active counts both vCPU pins
 * and temporary pins held while unmapping can drop mmu_lock.
 */
static struct kvm_pvm_mmu *pvm_get_mmu(struct kvm_vcpu *vcpu,
				       bool kernel, bool may_block)
{
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);
	struct kvm_pvm *pvm = kvm_to_pvm(vcpu->kvm);
	struct kvm_pvm_mmu **pool = kernel ? pvm->skern_mmus : pvm->suser_mmus;
	size_t pool_size = kernel ? pvm->skern_mmus_size : pvm->suser_mmus_size;
	size_t *next = kernel ? &pvm->skern_mmus_next : &pvm->suser_mmus_next;
	struct kvm_pvm_mmu *own = kernel ? pv->skern_mmu : pv->suser_mmu;
	struct kvm_pvm_mmu *mmu = NULL;
	u64 ttbr0 = ctxt_sys_reg(&vcpu->arch.ctxt, TTBR0_EL1) & TTBRx_EL1_BADDR;
	u64 ttbr1 = ctxt_sys_reg(&vcpu->arch.ctxt, TTBR1_EL1) & TTBRx_EL1_BADDR;
	u64 tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);
	u64 sctlr = ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1);
	u64 mair = ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1);
	u16 asid = pvm_guest_asid(vcpu, tcr);
	unsigned int va_bits = kernel ? PVM_SHADOW_S1_VA_BITS :
				64 - FIELD_GET(TCR_T0SZ_MASK, tcr);
	unsigned long seq = pvm->invalidate_seq;
	size_t i;

	lockdep_assert_held_write(&vcpu->kvm->mmu_lock);
	if (!pool_size) {
		/* Unreachable once this vCPU has initialised the pools. */
		kvm_err("PVM: empty %s context pool\n", kernel ? "kernel" : "user");
		return ERR_PTR(-EINVAL);
	}

	/* A published context that already carries this regime. */
	for (i = 0; i < pool_size; i++) {
		struct kvm_pvm_mmu *candidate = pool[i];

		if (candidate->used &&
		    pvm_key_matches(candidate, kernel, tcr, sctlr, mair,
				    ttbr0, ttbr1, asid)) {
			candidate->active++;
			return candidate;
		}
	}

	/*
	 * This vCPU pins its own context, so reclaim cannot select it.
	 * VM-wide invalidation clears used before unmapping, but selection
	 * is blocked by invalidating until the unmap has finished. The
	 * withdrawn context can then be republished if its key still matches.
	 */
	if (own && !own->used &&
	    pvm_key_matches(own, kernel, tcr, sctlr, mair, ttbr0, ttbr1, asid)) {
		own->used = true;
		own->active++;
		return own;
	}

	/* A context nobody pins. */
	for (i = 0; i < pool_size; i++) {
		size_t index = (*next + i) % pool_size;

		if (!pool[index]->active) {
			mmu = pool[index];
			*next = (index + 1) % pool_size;
			break;
		}
	}

	/*
	 * The pool covers every regime its vCPUs can pin at once, so an
	 * exhausted pool is a sizing bug rather than a transient state: report
	 * it and let the caller retry instead of guessing a victim.
	 */
	if (!mmu) {
		kvm_err("PVM: no free %s context\n", kernel ? "kernel" : "user");
		return ERR_PTR(-EAGAIN);
	}

	/*
	 * The selected context had no pins. If it is also unpublished, it
	 * is new or fully unmapped: an in-progress unmap holds a pin.
	 * Pin before reclaim, which can release mmu_lock.
	 */
	mmu->active++;
	if (mmu->used) {
		mmu->used = false;
		pvm_unmap_mmu(mmu, may_block);
	}
	if (pvm->invalidating || pvm->invalidate_seq != seq) {
		pvm_put_mmu(mmu);
		return ERR_PTR(-EAGAIN);
	}
	mmu->ttbr0 = ttbr0;
	mmu->ttbr1 = ttbr1;
	mmu->tcr = tcr;
	mmu->sctlr = sctlr;
	mmu->mair = mair;
	mmu->asid = asid;
	mmu->mmu.pgt->ia_bits = va_bits;
	mmu->mmu.pgt->start_level = KVM_PGTABLE_MAX_LEVELS -
				   PVM_PGTABLE_LEVELS(va_bits);
	mmu->used = true;
	return mmu;
}

static bool pvm_user_va_bits_valid(u64 tcr)
{
	unsigned int va_bits = 64 - FIELD_GET(TCR_T0SZ_MASK, tcr);

	return va_bits >= PVM_SHADOW_S1_MIN_VA_BITS && va_bits <= 47;
}

static bool pvm_context_matches(struct kvm_pvm_mmu *mmu,
				struct kvm_vcpu *vcpu, bool kernel)
{
	u64 tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);
	u64 sctlr = ctxt_sys_reg(&vcpu->arch.ctxt, SCTLR_EL1);
	u64 mair = ctxt_sys_reg(&vcpu->arch.ctxt, MAIR_EL1);
	u64 ttbr0 = ctxt_sys_reg(&vcpu->arch.ctxt, TTBR0_EL1);
	u64 ttbr1 = ctxt_sys_reg(&vcpu->arch.ctxt, TTBR1_EL1);

	return mmu && mmu->used &&
	       pvm_key_matches(mmu, kernel, tcr, sctlr, mair,
			       ttbr0 & TTBRx_EL1_BADDR,
			       ttbr1 & TTBRx_EL1_BADDR,
			       pvm_guest_asid(vcpu, tcr));
}

static bool pvm_cached_contexts_match(struct kvm_vcpu *vcpu)
{
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);
	bool matches;

	read_lock(&vcpu->kvm->mmu_lock);
	if (kvm_to_pvm(vcpu->kvm)->invalidating)
		matches = false;
	else if (!kvm_pvm_vcpu_mmu_enabled(vcpu))
		matches = !pv->suser_mmu && !pv->skern_mmu;
	else
		matches = (pvm_user_va_bits_valid(ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1)) ?
			   pvm_context_matches(pv->suser_mmu, vcpu, false) :
			   !pv->suser_mmu) &&
			  pvm_context_matches(pv->skern_mmu, vcpu, true);
	read_unlock(&vcpu->kvm->mmu_lock);
	return matches;
}

int kvm_pvm_vcpu_select_mmu(struct kvm_vcpu *vcpu, bool may_block)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);
	struct kvm_pvm_mmu *user = NULL, *kernel = NULL;
	u64 tcr;
	unsigned long seq;
	int ret = 0;

	/* Pins survive scheduling; only a matching, published regime is reusable. */
	if (pvm_cached_contexts_match(vcpu))
		return 0;

	tcr = ctxt_sys_reg(&vcpu->arch.ctxt, TCR_EL1);

	write_lock(&kvm->mmu_lock);
	seq = kvm_to_pvm(kvm)->invalidate_seq;
	if (kvm_to_pvm(kvm)->invalidating) {
		ret = -EAGAIN;
		goto out;
	}
	if (kvm_pvm_vcpu_mmu_enabled(vcpu)) {
		kernel = pvm_get_mmu(vcpu, true, may_block);
		if (IS_ERR(kernel)) {
			ret = PTR_ERR(kernel);
			goto out;
		}
		/* Leave TTBR0 empty until the guest selects a supported width. */
		if (pvm_user_va_bits_valid(tcr)) {
			user = pvm_get_mmu(vcpu, false, may_block);
			if (IS_ERR(user)) {
				ret = PTR_ERR(user);
				pvm_put_mmu(kernel);
				goto out;
			}
		}
		if (kvm_to_pvm(kvm)->invalidating ||
		    kvm_to_pvm(kvm)->invalidate_seq != seq) {
			if (user)
				pvm_put_mmu(user);
			pvm_put_mmu(kernel);
			ret = -EAGAIN;
			goto out;
		}
	}
	if (pv->suser_mmu)
		pvm_put_mmu(pv->suser_mmu);
	if (pv->skern_mmu)
		pvm_put_mmu(pv->skern_mmu);
	pv->suser_mmu = user;
	pv->skern_mmu = kernel;
out:
	write_unlock(&kvm->mmu_lock);
	return ret;
}

void kvm_pvm_vcpu_put_mmu(struct kvm_vcpu *vcpu)
{
	struct kvm_pvm_vcpu *pv = vcpu_to_pvm(vcpu);

	write_lock(&vcpu->kvm->mmu_lock);
	if (pv->suser_mmu) {
		pvm_put_mmu(pv->suser_mmu);
		pv->suser_mmu = NULL;
	}
	if (pv->skern_mmu) {
		pvm_put_mmu(pv->skern_mmu);
		pv->skern_mmu = NULL;
	}
	write_unlock(&vcpu->kvm->mmu_lock);
}

void kvm_pvm_unmap_all(struct kvm *kvm, bool may_block)
{
	struct kvm_pvm *pvm = kvm_to_pvm(kvm);
	size_t i;

	lockdep_assert_held_write(&kvm->mmu_lock);
	if (!kvm->arch.mmu.pgt)
		return;
	pvm->invalidating++;
	pvm->invalidate_seq++;
	/*
	 * Unpublished, unpinned contexts have no guest mappings. A context
	 * being unmapped keeps an active pin even while mmu_lock is dropped,
	 * so another invalidation must not skip it until withdrawal completes.
	 */
	for (i = 0; i < pvm->suser_mmus_size; i++) {
		struct kvm_pvm_mmu *mmu = pvm->suser_mmus[i];

		if (!mmu->used && !mmu->active)
			continue;
		mmu->used = false;
		mmu->active++;
		pvm_unmap_mmu(mmu, may_block);
		pvm_put_mmu(mmu);
	}
	for (i = 0; i < pvm->skern_mmus_size; i++) {
		struct kvm_pvm_mmu *mmu = pvm->skern_mmus[i];

		if (!mmu->used && !mmu->active)
			continue;
		mmu->used = false;
		mmu->active++;
		pvm_unmap_mmu(mmu, may_block);
		pvm_put_mmu(mmu);
	}
	unmap_stage2_range(&kvm->arch.mmu, 0,
			   min_t(u64, kvm_phys_size(kvm),
				 PVM_SHADOW_S1_KERNEL_BASE), may_block);
	pvm->invalidate_seq++;
	pvm->invalidating--;
}
