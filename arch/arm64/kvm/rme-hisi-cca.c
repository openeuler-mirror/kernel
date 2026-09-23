// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2026, The Linux Foundation. All rights reserved.
 */

#include <asm/kvm_emulate.h>
#include <asm/kvm_rme_hisi_cca.h>
#include <asm/rmi_cmds.h>
#include <asm/stage2_pgtable.h>

#define RMM_PAGE_SHIFT		12
#define RMM_PAGE_SIZE		BIT(RMM_PAGE_SHIFT)

#define RMM_RTT_BLOCK_LEVEL	2
#define RMM_RTT_MAX_LEVEL	3

/* See ARM64_HW_PGTABLE_LEVEL_SHIFT() */
#define RMM_RTT_LEVEL_SHIFT(l)	\
	((RMM_PAGE_SHIFT - 3) * (4 - (l)) + 3)
#define RMM_L2_BLOCK_SIZE	BIT(RMM_RTT_LEVEL_SHIFT(2))
#define RMM_L1_BLOCK_SIZE	BIT(RMM_RTT_LEVEL_SHIFT(1))

#define RTT_ENTRY_NUM	512U

enum HISI_CCA_GRANULE_TYPES {
	HISI_CCA_GRANULE_NORMAL,
	HISI_CCA_GRANULE_DEV,
	HISI_CCA_GRANULE_NS,
	HISI_CCA_GRANULE_TYPES_NUM
};

static inline int _rmi_cca_hisi_delegate_range(unsigned long start_addr,
					      unsigned long size)
{
	struct arm_smccc_1_2_regs regs = {
		SMC_RMI_HISI_EXT, CCA_HISI_DELEGATE_RANGE,
		start_addr, size
	};

	arm_smccc_1_2_smc(&regs, &regs);

	return regs.a0;
}

static int get_start_level(struct realm *realm)
{
	return 4 - ((realm->ia_bits - 8) / (RMM_PAGE_SHIFT - 3));
}

static inline unsigned long rme_rtt_level_mapsize(int level)
{
	if (WARN_ON(level > RMM_RTT_MAX_LEVEL))
		return RMM_PAGE_SIZE;

	return (1UL << RMM_RTT_LEVEL_SHIFT(level));
}

static int find_data_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = RMM_RTT_MAX_LEVEL;
	unsigned long hugetlb_pagesz = HPAGE_SIZE;

	hugetlb_pagesz = huge_page_size(&default_hstate);
	while (level > get_start_level(realm)) {
		unsigned long map_size = rme_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;
		if (map_size > hugetlb_pagesz)
			break;
		level--;
	}

	return level;
}

static int find_map_level(struct realm *realm,
			  unsigned long start,
			  unsigned long end)
{
	int level = RMM_RTT_MAX_LEVEL;

	while (level > get_start_level(realm)) {
		unsigned long map_size = rme_rtt_level_mapsize(level - 1);

		if (!IS_ALIGNED(start, map_size) ||
		    (start + map_size) > end)
			break;

		level--;
	}

	return level;
}

static bool pages_are_consecutive(struct page **pages, int num)
{
	for (int i = 1; i < num; i++) {
		if (page_to_phys(pages[i]) - page_to_phys(pages[i - 1])
		    != PAGE_SIZE)
			return false;
	}

	return true;
}

static int hisi_cca_create_data_page_unknown(struct realm *realm,
					     unsigned long ipa,
					     struct page *page)
{
	phys_addr_t rd = virt_to_phys(realm->rd);
	phys_addr_t phys = page_to_phys(page);
	int ret, offset;

	for (offset = 0; offset < PAGE_SIZE; offset += RMM_PAGE_SIZE) {
		if (rmi_granule_delegate_get(phys, realm)) {
			/*
			 * It's likely we raced with another VCPU on the same
			 * fault. Assume the other VCPU has handled the fault
			 * and return to the guest.
			 */
			return 0;
		}

		ret = rmi_data_create_unknown(rd, phys, ipa);
		if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			/* Create missing RTTs and retry */
			int level = RMI_RETURN_INDEX(ret);

			WARN_ON(level == RMM_RTT_MAX_LEVEL);

			ret = realm_create_rtt_levels(realm, ipa, level,
						      RMM_RTT_MAX_LEVEL,
						      NULL);
			if (ret)
				goto err_undelegate;

			ret = rmi_data_create_unknown(rd, phys, ipa);
		}

		if (WARN_ON(ret))
			goto err_undelegate;

		phys += RMM_PAGE_SIZE;
		ipa += RMM_PAGE_SIZE;
	}

	return 0;

err_undelegate:
	if (WARN_ON(rmi_granule_undelegate(phys))) {
		/* Page can't be returned to NS world so is lost */
		get_page(phys_to_page(phys));
	}

	while (offset > 0) {
		unsigned long data, top;

		phys -= RMM_PAGE_SIZE;
		offset -= RMM_PAGE_SIZE;
		ipa -= RMM_PAGE_SIZE;

		WARN_ON(rmi_data_destroy(rd, ipa, &data, &top));

		if (WARN_ON(rmi_granule_undelegate(phys))) {
			/* Page can't be returned to NS world so is lost */
			get_page(phys_to_page(phys));
		}
	}
	return -ENXIO;
}

static int hisi_cca_create_data_block(struct realm *realm, unsigned long ipa,
				      struct page **dst_pages,
				      struct page *tmp_block,
				      unsigned long flags)
{
	phys_addr_t dst_phys, tmp_phys;
	int ret;

	memcpy(page_address(tmp_block), page_address(dst_pages[0]),
	       RMM_L2_BLOCK_SIZE);

	dst_phys = page_to_phys(dst_pages[0]);
	tmp_phys = page_to_phys(tmp_block);

	if (rmi_cca_hisi_delegate_range_get(dst_phys, RMM_L2_BLOCK_SIZE, realm) != RMI_SUCCESS)
		return -ENXIO;

	ret = rmi_cca_hisi_block_create(virt_to_phys(realm->rd), dst_phys, ipa,
					tmp_phys, flags);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry. */
		int err_level = RMI_RETURN_INDEX(ret);

		ret = realm_create_rtt_levels(realm, ipa, err_level,
					      RMM_RTT_BLOCK_LEVEL, NULL);
		if (ret)
			goto err_undelegate;

		ret = rmi_cca_hisi_block_create(virt_to_phys(realm->rd), dst_phys,
						ipa, tmp_phys, flags);
	}

	if (ret)
		goto err_undelegate;

	return 0;

err_undelegate:
	if (WARN_ON(rmi_cca_hisi_undelegate_range(dst_phys, RMM_L2_BLOCK_SIZE))) {
		for (int i = 0, offset = 0; offset < RMM_L2_BLOCK_SIZE;
		     i++, offset += PAGE_SIZE) {
			/* Pages can't be returned to NS world so are lost. */
			get_page(dst_pages[i]);
		}
	}
	return -ENXIO;
}

static int hisi_cca_create_data_block_unknown(struct realm *realm,
					      struct page **dst_pages,
					      unsigned long ipa,
					      unsigned long level)
{
	unsigned long map_size = rme_rtt_level_mapsize(level);
	phys_addr_t dst_phys = page_to_phys(dst_pages[0]);
	int ret;

	if (rmi_cca_hisi_delegate_range_get(dst_phys, map_size, realm)) {
		/* Race with another thread. */
		return 0;
	}

	ret = rmi_cca_hisi_block_create_unknown(virt_to_phys(realm->rd),
						dst_phys, ipa, level);
	if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
		/* Create missing RTTs and retry. */
		int err_level = RMI_RETURN_INDEX(ret);

		ret = realm_create_rtt_levels(realm, ipa, err_level,
					      level, NULL);
		if (ret)
			goto err_undelegate;

		ret = rmi_cca_hisi_block_create_unknown(virt_to_phys(realm->rd),
							dst_phys, ipa, level);
	}
	if (ret)
		goto err_undelegate;

	return 0;

err_undelegate:
	if (WARN_ON(rmi_cca_hisi_undelegate_range(dst_phys, level))) {
		for (int i = 0, offset = 0; offset < rme_rtt_level_mapsize(level);
		     i++, offset += PAGE_SIZE) {
			/* Pages can't be returned to NS world so are lost. */
			get_page(dst_pages[i]);
		}
	}

	return -ENXIO;
}

int realm_hisi_cca_populate_region(struct kvm *kvm, phys_addr_t ipa_base,
				   phys_addr_t ipa_end, phys_addr_t *ipa_top,
				   u32 flags)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_memory_slot *memslot;
	struct page *tmp_pages = NULL;
	unsigned long data_flags = 0;
	gfn_t base_gfn, top_gfn;
	int nr_pages, nr_pinned;
	struct page **pages;
	unsigned int order;
	unsigned long hva;
	bool block_map;
	int idx;
	int ret;

	if (ipa_base == ipa_end)
		return 0;

	if (flags & KVM_ARM_RME_POPULATE_FLAGS_MEASURE)
		data_flags = RMI_MEASURE_CONTENT;

	if (ipa_base == ALIGN_DOWN(ipa_base, RMM_L2_BLOCK_SIZE) &&
	    ipa_end - ipa_base >= RMM_L2_BLOCK_SIZE) {
		*ipa_top = ipa_base + RMM_L2_BLOCK_SIZE;
		block_map = true;
	} else {
		*ipa_top = min(ipa_end, ALIGN_DOWN(ipa_base + RMM_L2_BLOCK_SIZE,
						   RMM_L2_BLOCK_SIZE));
		block_map = false;
	}

	base_gfn = gpa_to_gfn(ipa_base);
	top_gfn = gpa_to_gfn(*ipa_top);
	nr_pages = top_gfn - base_gfn;

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, base_gfn);
	if (!memslot) {
		ret = -EFAULT;
		goto out_srcu;
	}

	/* We require the region to be contained within a single memslot. */
	if (memslot->base_gfn + memslot->npages < top_gfn) {
		ret = -EINVAL;
		goto out_srcu;
	}

	hva = gfn_to_hva_memslot(memslot, gpa_to_gfn(ipa_base));
	if (kvm_is_error_hva(hva)) {
		ret = -EINVAL;
		goto out_srcu;
	}

	pages = kmalloc(RTT_ENTRY_NUM * sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		ret = -ENOMEM;
		goto out_srcu;
	}

	nr_pinned = pin_user_pages_fast(hva, nr_pages, FOLL_WRITE, pages);
	if (nr_pinned != nr_pages) {
		ret = -EFAULT;
		goto out_pin;
	}

	if (block_map && !IS_ALIGNED(page_to_phys(pages[0]), RMM_L2_BLOCK_SIZE))
		block_map = false;

	if (block_map && !pages_are_consecutive(pages, nr_pinned))
		block_map = false;

	if (block_map)
		order = get_order(RMM_L2_BLOCK_SIZE);
	else
		order = get_order(RMM_PAGE_SIZE);

	tmp_pages = alloc_pages(GFP_KERNEL, order);
	if (!tmp_pages) {
		ret = -ENOMEM;
		goto out_pin;
	}

	if (block_map) {
		ret = hisi_cca_create_data_block(realm, ipa_base, pages,
						 tmp_pages, data_flags);
		if (ALIGN(ipa_base, RMM_L1_BLOCK_SIZE) ==
		    (ipa_base + RMM_L2_BLOCK_SIZE))
			fold_rtt(realm, ALIGN_DOWN(ipa_base, RMM_L1_BLOCK_SIZE),
				 RMM_RTT_BLOCK_LEVEL);
	} else {
		for (int i = 0; i < nr_pinned; i++) {
			ret = realm_create_protected_data_page(realm, ipa_base,
							       pages[i],
							       tmp_pages,
							       data_flags);
			if (ret)
				break;
			ipa_base += RMM_PAGE_SIZE;
		}
	}

out_pin:
	unpin_user_pages(pages, nr_pinned);
	kfree(pages);
	if (tmp_pages)
		__free_pages(tmp_pages, order);
out_srcu:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

static int hisi_cca_map_range(struct kvm *kvm, unsigned long ipa_base,
			      int map_level, phys_addr_t *ipa_top)
{
	struct realm *realm = &kvm->arch.realm;
	struct kvm_memory_slot *memslot;
	gfn_t base_gfn, top_gfn;
	int nr_pages, nr_pinned;
	struct page **pages;
	unsigned long hva, map_size;
	phys_addr_t base_pa;
	int idx, ret;

	map_size = rme_rtt_level_mapsize(map_level);

	base_gfn = gpa_to_gfn(ipa_base);
	top_gfn = gpa_to_gfn(ipa_base + map_size);

	nr_pages = top_gfn - base_gfn;

	idx = srcu_read_lock(&kvm->srcu);
	memslot = gfn_to_memslot(kvm, base_gfn);
	if (!memslot) {
		ret = -EFAULT;
		goto out_srcu;
	}

	/* We require the region to be contained within a single memslot. */
	if (memslot->base_gfn + memslot->npages < top_gfn) {
		ret = -EFAULT;
		goto out_srcu;
	}

	pages = kmalloc(nr_pages * sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		ret = -ENOMEM;
		goto out_srcu;
	}

	hva = gfn_to_hva_memslot(memslot, gpa_to_gfn(ipa_base));
	nr_pinned = pin_user_pages_fast(hva, nr_pages, FOLL_WRITE, pages);
	if (nr_pinned != nr_pages) {
		ret = -EFAULT;
		goto out_pin;
	}

	base_pa = page_to_phys(pages[0]);
	if (IS_ALIGNED(base_pa, map_size) &&
	    pages_are_consecutive(pages, nr_pinned)) {
		ret = hisi_cca_create_data_block_unknown(realm, pages, ipa_base,
							 map_level);
	} else {
		unsigned long tmp_ipa = ipa_base;

		if (map_level + 1 < RMM_RTT_MAX_LEVEL) {
			ret = -EAGAIN;
			goto out_pin;
		}
		for (int i = 0; i < nr_pinned; i++) {
			ret = hisi_cca_create_data_page_unknown(realm, tmp_ipa,
								pages[i]);
			if (ret)
				break;
			tmp_ipa += RMM_PAGE_SIZE;
		}
	}
	*ipa_top = ipa_base + map_size;

out_pin:
	unpin_user_pages(pages, nr_pinned);
	kfree(pages);
out_srcu:
	srcu_read_unlock(&kvm->srcu, idx);
	return ret;
}

int realm_hisi_cca_map_ram(struct kvm *kvm,
			   struct arm_rme_map_ram_args *args)
{
	phys_addr_t ipa_base, ipa_end, next_ipa;
	int ret, map_level;

	if (kvm_realm_state(kvm) != REALM_STATE_NEW)
		return -EINVAL;

	ipa_base = args->ram_base;
	ipa_end = ipa_base + args->ram_size;

	if (!IS_ALIGNED(ipa_base, PAGE_SIZE) ||
	    !IS_ALIGNED(ipa_end, PAGE_SIZE) ||
	    ipa_base > ipa_end)
		return -EINVAL;

	if (ipa_base == ipa_end)
		return 0;

	while (ipa_base < ipa_end) {
		map_level = find_data_map_level(&kvm->arch.realm, ipa_base, ipa_end);
		ret = hisi_cca_map_range(kvm, ipa_base, map_level, &next_ipa);
		if (ret) {
			if (ret == -EAGAIN)
				ret = hisi_cca_map_range(kvm, ipa_base, map_level + 1, &next_ipa);
			if (ret)
				break;
		}

		ipa_base = next_ipa;
		cond_resched();
	}

	return ret;
}

static int hisi_cca_destroy_data(struct realm *realm, unsigned long ipa,
				 unsigned long *next_addr)
{
	unsigned long pa, size, granule_type, offset;
	unsigned long rd = virt_to_phys(realm->rd);
	int ret;

	ret = rmi_cca_hisi_data_destroy(rd, ipa, &pa, &size, &granule_type,
					next_addr);
	if (WARN_ON(ret))
		return -ENXIO;

	if (granule_type == HISI_CCA_GRANULE_NORMAL) {
		ret = rmi_cca_hisi_undelegate_range(pa, size);
		/*
		 * If the undelegate fails then something has gone seriously
		 * wrong: take an extra reference to just leak pages.
		 */
		if (WARN_ON(ret)) {
			for (offset = 0; offset < size; offset += PAGE_SIZE)
				get_page(phys_to_page(pa + offset));
		}
	}

	return 0;
}

void realm_hisi_cca_destroy_data_range(struct kvm *kvm, unsigned long start,
				       unsigned long end)
{
	struct realm *realm = &kvm->arch.realm;
	unsigned long next_addr, addr;
	int ret;

	for (addr = start; addr < end; addr = next_addr) {
		ret = hisi_cca_destroy_data(realm, addr, &next_addr);
		if (ret)
			break;
		cond_resched_rwlock_write(&kvm->mmu_lock);
	}
}

static int rtt_complement(struct realm *realm, unsigned long ipa,
			  int walk_level, int level)
{
	/*
	 * Walk level could be -1 if the LPA2 feature is enabled.
	 * RMM adds 1 to both of protected level and unprotected level so that
	 * their values can be correctly delieverd.
	 */
	int protected_level = (walk_level & 0xF) - 1;
	int unprotected_level = ((walk_level >> 4) & 0xF) - 1;
	int ret = 0;

	level = max(max(protected_level, unprotected_level), level);
	if (protected_level < level)
		ret = realm_create_rtt_levels(realm, ipa, protected_level,
					      level, NULL);

	if (ret)
		return ret;

	ipa = (1UL << (realm->ia_bits - 1)) | ipa;
	if (unprotected_level < level)
		ret = realm_create_rtt_levels(realm, ipa, unprotected_level,
					      level, NULL);

	return ret;
}

int realm_hisi_cca_set_ipa_state(struct kvm_vcpu *vcpu, unsigned long start,
				 unsigned long end, unsigned long ripas,
				 unsigned long *top_ipa)
{
	struct kvm *kvm = vcpu->kvm;
	struct realm *realm = &kvm->arch.realm;
	struct realm_rec *rec = vcpu->arch.rec;
	phys_addr_t rd_phys = virt_to_phys(realm->rd);
	phys_addr_t rec_phys = virt_to_phys(rec->rec_page);
	unsigned long ipa = start;
	int ret = 0;

	while (ipa < end) {
		unsigned long next;

		ret = rmi_rtt_set_ripas(rd_phys, rec_phys, ipa, end, &next);
		if (RMI_RETURN_STATUS(ret) == RMI_SUCCESS) {
			ipa = next;
		} else if (RMI_RETURN_STATUS(ret) == RMI_ERROR_RTT) {
			int walk_level = RMI_RETURN_INDEX(ret);
			int level = find_map_level(realm, ipa, end);

			ret = rtt_complement(realm, ipa, walk_level, level);
			if (ret)
				break;
			/* Retry with RTTs created */
		} else {
			WARN(1, "Unexpected error in %s: %#x\n", __func__,
			     ret);
			ret = -ENXIO;
			break;
		}
	}

	*top_ipa = ipa;

	return ret;
}

int rmi_cca_hisi_delegate_range_get(unsigned long start_addr, unsigned long size, void *realm_p)
{
	unsigned long start = start_addr;
	unsigned long end = start_addr + size;
	struct folio *folio;
	struct realm *realm = (struct realm *)realm_p;

	while (start < end) {
		folio = page_folio(phys_to_page(start));
		if (!folio)
			return -EINVAL;

		if (folio_test_hugetlb(folio)) {
			if (rme_isolate_hugetlb(folio)) {
				folio_put(folio);
				if (realm) {
					int ret;

					ret = realm_add_hugetlb_folios(realm, folio);
					if (ret)
						return ret;
				}
			}
		} else if (folio_test_lru(folio)) {
			if (folio_isolate_lru(folio)) {
				folio_put(folio);
				if (realm) {
					unsigned long flags;

					spin_lock_irqsave(&realm->realm_lock, flags);
					folio_get(folio);
					list_add(&folio->lru, &realm->page_list);
					spin_unlock_irqrestore(&realm->realm_lock, flags);
				}
			}
		}
		start = (folio_pfn(folio) + folio_nr_pages(folio)) * PAGE_SIZE;
	}
	return _rmi_cca_hisi_delegate_range(start_addr, size);
}
