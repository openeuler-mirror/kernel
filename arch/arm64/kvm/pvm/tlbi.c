// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Huawei Technologies Co., Ltd.
 * Author: Kunkun Jiang <jiangkunkun@huawei.com>
 */

#include <linux/sort.h>
#include <linux/kvm_host.h>

#include <asm/insn.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_pvm.h>
#include <asm/sysreg.h>
#include <asm/tlbflush.h>
#include <asm/virt.h>

#include "mmu.h"
#include "tlbi.h"

void kvm_pvm_flush_tlb_asid(u16 asid)
{
	dsb(ishst);
	__tlbi(aside1is, __TLBI_VADDR(0, asid));
	dsb(ish);
}

static u16 pvm_mmu_asid(struct kvm_s2_mmu *mmu)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);

	if (mmu == &kvm->arch.mmu)
		return kvm_to_pvm(kvm)->identity_shadow_asid;
	return container_of(mmu, struct kvm_pvm_mmu, mmu)->shadow_asid;
}

static bool pvm_mmu_is_kernel(struct kvm_s2_mmu *mmu)
{
	struct kvm *kvm = kvm_s2_mmu_to_kvm(mmu);

	return mmu != &kvm->arch.mmu &&
	       container_of(mmu, struct kvm_pvm_mmu, mmu)->kern_pgd;
}

static unsigned int pvm_batch_key(const struct kvm_pvm_unmap_page *page)
{
	struct kvm_s2_mmu *mmu = page->pgt->mmu;

	/* Shared kernel translations must be invalidated across all ASIDs. */
	return pvm_mmu_is_kernel(mmu) ? BIT(16) : pvm_mmu_asid(mmu);
}

static int pvm_batch_compare(const void *a, const void *b)
{
	const struct kvm_pvm_unmap_page *left = a, *right = b;
	unsigned int lk = pvm_batch_key(left), rk = pvm_batch_key(right);

	if (lk != rk)
		return lk < rk ? -1 : 1;
	return left->addr < right->addr ? -1 : left->addr > right->addr;
}

void kvm_pvm_flush_shadow_tlb_batch(struct kvm_pvm_unmap_page *pages,
				    unsigned int nr)
{
	unsigned int i = 0;

	/* Reordering the targets does not change the saved leaf-cleanup records. */
	sort(pages, nr, sizeof(*pages), pvm_batch_compare, NULL);
	dsb(ishst);
	while (i < nr) {
		unsigned int key = pvm_batch_key(&pages[i]);
		u64 start = pages[i].addr, end = start + PAGE_SIZE, nr_pages;

		i++;
		while (i < nr && pvm_batch_key(&pages[i]) == key &&
		       pages[i].addr <= end) {
			end = max(end, pages[i].addr + PAGE_SIZE);
			i++;
		}
		nr_pages = (end - start) >> PAGE_SHIFT;
		if (key == BIT(16)) {
			start = sign_extend64(start, PVM_SHADOW_S1_VA_BITS - 1);
			__flush_tlb_range_op(vaae1is, start, nr_pages,
					     PAGE_SIZE, 0, 0, false);
		} else {
			__flush_tlb_range_op(vae1is, start, nr_pages,
					     PAGE_SIZE, key, 0, false);
		}
	}
	dsb(ish);
	isb();
}

void kvm_pvm_flush_shadow_tlb(struct kvm_s2_mmu *mmu)
{
	if (pvm_mmu_is_kernel(mmu)) {
		dsb(ishst);
		__tlbi(vmalle1is);
		dsb(ish);
		isb();
	} else {
		kvm_pvm_flush_tlb_asid(pvm_mmu_asid(mmu));
	}
}

/**
 * kvm_pvm_flush_shadow_tlb_ipa() - Invalidate a shadow mapping or subtree
 * @mmu: Shadow translation context owning the mapping.
 * @addr: Address within the shadow mapping being invalidated.
 * @level: Level of the removed shadow page-table descriptor.
 *
 * For a table descriptor, use @level to determine the subtree's address
 * range, not as a hardware TTL hint. Range invalidation must cover all
 * translation levels, including cached intermediate walks. Fall back to
 * context invalidation when range maintenance is unavailable or unsuitable.
 * Complete the broadcast invalidation before returning so the caller can
 * release the affected page-table references.
 */
void kvm_pvm_flush_shadow_tlb_ipa(struct kvm_s2_mmu *mmu, u64 addr, int level)
{
	if (level != KVM_PGTABLE_MAX_LEVELS - 1) {
		if ((level == 1 || level == 2) &&
		    system_supports_tlb_range()) {
			u64 size = kvm_granule_size(level);
			u64 start = ALIGN_DOWN(addr, size);

			dsb(ishst);
			/* Invalidate intermediate walks as well as the retired leaves. */
			if (pvm_mmu_is_kernel(mmu)) {
				start = sign_extend64(start, PVM_SHADOW_S1_VA_BITS - 1);
				__flush_tlb_range_op(vaae1is, start, size >> PAGE_SHIFT,
						     PAGE_SIZE, 0, 0, false);
			} else {
				__flush_tlb_range_op(vae1is, start, size >> PAGE_SHIFT,
						     PAGE_SIZE, pvm_mmu_asid(mmu), 0, false);
			}
			dsb(ish);
			return;
		}
		kvm_pvm_flush_shadow_tlb(mmu);
		return;
	}
	dsb(ishst);
	if (pvm_mmu_is_kernel(mmu)) {
		/* The software walker uses a folded TTBR1 address. */
		addr = sign_extend64(addr, PVM_SHADOW_S1_VA_BITS - 1);
		__tlbi(vaae1is, __TLBI_VADDR(addr, 0));
	} else {
		__tlbi(vae1is, __TLBI_VADDR(addr, pvm_mmu_asid(mmu)));
	}
	dsb(ish);
}

void kvm_pvm_flush_shadow_tlb_ipa_nsh(struct kvm_s2_mmu *mmu, u64 addr, int level)
{
	/* Permission grants may leave other CPUs to fault on their old permissions. */
	if (level != KVM_PGTABLE_MAX_LEVELS - 1) {
		kvm_pvm_flush_shadow_tlb_ipa(mmu, addr, level);
		return;
	}

	dsb(nshst);
	if (pvm_mmu_is_kernel(mmu)) {
		addr = sign_extend64(addr, PVM_SHADOW_S1_VA_BITS - 1);
		__tlbi(vaae1, __TLBI_VADDR(addr, 0));
	} else {
		__tlbi(vae1, __TLBI_VADDR(addr, pvm_mmu_asid(mmu)));
	}
	dsb(nsh);
	isb();
}

enum pvm_tlbi_op {
	PVM_TLBI_UNSUPPORTED,
	PVM_TLBI_ALL,
	PVM_TLBI_ASID,
	PVM_TLBI_VA_ASID,
	PVM_TLBI_VA_ALL_ASIDS,
};

/*
 * Decode exact architectural encodings, including shareability and last-level
 * variants. The backend conservatively broadcasts invalidation across vCPUs
 * and revokes all matching levels for each accepted variant.
 */
static enum pvm_tlbi_op pvm_decode_tlbi(u32 insn)
{
	if (!aarch64_insn_is_tlbi(insn))
		return PVM_TLBI_UNSUPPORTED;

	switch (insn & GENMASK(20, 5)) {
	case OP_TLBI_VMALLE1:
	case OP_TLBI_VMALLE1IS:
		return PVM_TLBI_ALL;
	case OP_TLBI_ASIDE1:
	case OP_TLBI_ASIDE1IS:
		return PVM_TLBI_ASID;
	case OP_TLBI_VAE1:
	case OP_TLBI_VAE1IS:
	case OP_TLBI_VALE1:
	case OP_TLBI_VALE1IS:
		return PVM_TLBI_VA_ASID;
	case OP_TLBI_VAAE1:
	case OP_TLBI_VAAE1IS:
	case OP_TLBI_VAALE1:
	case OP_TLBI_VAALE1IS:
		return PVM_TLBI_VA_ALL_ASIDS;
	default:
		return PVM_TLBI_UNSUPPORTED;
	}
}

int kvm_pvm_emulate_tlbi(struct kvm_vcpu *vcpu, u32 insn)
{
	enum pvm_tlbi_op op;
	u64 val, addr;

	if (!is_pvm_mode() || !vcpu_mode_priv(vcpu))
		return 0;

	op = pvm_decode_tlbi(insn);
	if (op == PVM_TLBI_UNSUPPORTED)
		return 0;

	val = vcpu_get_reg(vcpu, insn & 0x1f);
	addr = kvm_pvm_shadow_s1_addr(val << 12);
	/* Revoke software mappings too, or hardware can refill stale translations. */
	write_lock(&vcpu->kvm->mmu_lock);
	switch (op) {
	case PVM_TLBI_VA_ASID:
		kvm_pvm_unmap_shadow_va(vcpu->kvm, addr, val >> 48);
		break;
	case PVM_TLBI_VA_ALL_ASIDS:
		kvm_pvm_unmap_shadow_range(vcpu->kvm, addr, PAGE_SIZE);
		break;
	case PVM_TLBI_ASID:
		kvm_pvm_unmap_shadow_asid(vcpu->kvm, val >> 48);
		break;
	case PVM_TLBI_ALL:
	default:
		kvm_pvm_unmap_shadows(vcpu->kvm, true);
		break;
	}
	write_unlock(&vcpu->kvm->mmu_lock);
	kvm_incr_pc(vcpu);
	return 1;
}
