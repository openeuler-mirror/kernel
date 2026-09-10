// SPDX-License-Identifier: GPL-2.0-only
/*
 * CCA Realm page table allocator.
 *
 * Copyright (c) 2026 Hisilicon Limited.
 * Author: Zhang Wei <zhangwei375@huawei.com>
 */

#define pr_fmt(fmt)	"realm io-pgtable: " fmt

#include <linux/pci.h>
#include <asm/rmi_cmds.h>
#include <asm/hisi_cca_da.h>
#include <linux/io-pgtable.h>

#include "io-pgtable-arm.h"

#define REALM_MAX_ADDR_BITS		48
#define REALM_S2_MAX_CONCAT_PAGES	16
#define REALM_MAX_LEVELS		4

/* Page table bits */
#define REALM_PTE_TYPE_SHIFT		0
#define REALM_PTE_TYPE_MASK		0x3

#define REALM_PTE_TYPE_BLOCK		1
#define REALM_PTE_TYPE_TABLE		3
#define REALM_PTE_TYPE_PAGE		3

#define REALM_PTE_ADDR_MASK		GENMASK_ULL(47, 12)

#define REALM_PTE_XN			(((realm_iopte)3) << 53)
#define REALM_PTE_AF			(((realm_iopte)1) << 10)
#define REALM_PTE_SH_IS			(((realm_iopte)3) << 8)
#define REALM_PTE_NS			(((realm_iopte)1) << 5)

/* Stage-2 PTE */
#define REALM_PTE_HAP_FAULT		(((realm_iopte)0) << 6)
#define REALM_PTE_HAP_READ		(((realm_iopte)1) << 6)
#define REALM_PTE_HAP_WRITE		(((realm_iopte)2) << 6)
#define REALM_PTE_MEMATTR_OIWB		(((realm_iopte)0xf) << 2)
#define REALM_PTE_MEMATTR_NC		(((realm_iopte)0x5) << 2)
#define REALM_PTE_MEMATTR_DEV		(((realm_iopte)0x1) << 2)

/* Register bits */
#define REALM_VTCR_SL0_MASK		0x3

/* Struct accessors */
#define io_pgtable_to_data(x)						\
	container_of((x), struct realm_io_pgtable, iop)

#define io_pgtable_ops_to_data(x)					\
	io_pgtable_to_data(io_pgtable_ops_to_pgtable(x))

/*
 * Calculate the right shift amount to get to the portion describing level l
 * in a virtual address mapped by the pagetable in d.
 */
#define REALM_LVL_SHIFT(l, d)						\
	(((REALM_MAX_LEVELS - (l)) * (d)->bits_per_level) +		\
	ilog2(sizeof(realm_iopte)))

#define REALM_GRANULE(d)						\
	(sizeof(realm_iopte) << (d)->bits_per_level)
#define REALM_PGD_SIZE(d)						\
	(sizeof(realm_iopte) << (d)->pgd_bits)
#define REALM_PTES_PER_TABLE(d)						\
	(REALM_GRANULE(d) >> ilog2(sizeof(realm_iopte)))

/*
 * Calculate the index at level l used to map virtual address a using the
 * pagetable in d.
 */
#define REALM_PGD_IDX(l, d)						\
	((l) == (d)->start_level ? (d)->pgd_bits - (d)->bits_per_level : 0)

#define REALM_LVL_IDX(a, l, d)						\
	(((u64)(a) >> REALM_LVL_SHIFT(l, d)) &			\
	 ((1 << ((d)->bits_per_level + REALM_PGD_IDX(l, d))) - 1))

/* Calculate the block/page mapping size at level l for pagetable in d. */
#define REALM_BLOCK_SIZE(l, d)	(1ULL << REALM_LVL_SHIFT(l, d))

/* IOPTE accessors */
#define iopte_deref(pte, d) __va(iopte_to_paddr(pte, d))

#define iopte_type(pte)					\
	(((pte) >> REALM_PTE_TYPE_SHIFT) & REALM_PTE_TYPE_MASK)

typedef u64 realm_iopte;

struct realm_io_pgtable {
	struct io_pgtable iop;
	int pgd_bits;
	int start_level;
	int bits_per_level;
	void *pgd;
	bool ns;
	void *ns_pgd;
};

static inline bool iopte_leaf(realm_iopte pte, int lvl,
			      enum io_pgtable_fmt fmt)
{
	if (lvl == (REALM_MAX_LEVELS - 1))
		return iopte_type(pte) == REALM_PTE_TYPE_PAGE;

	return iopte_type(pte) == REALM_PTE_TYPE_BLOCK;
}

static phys_addr_t iopte_to_paddr(realm_iopte pte,
				  struct realm_io_pgtable *data)
{
	u64 paddr = pte & REALM_PTE_ADDR_MASK;

	if (REALM_GRANULE(data) < SZ_64K)
		return paddr;

	/* Rotate the packed high-order bits back to the top */
	return (paddr | (paddr << (48 - 12))) & (REALM_PTE_ADDR_MASK << 4);
}

static realm_iopte paddr_to_iopte(phys_addr_t paddr,
				     struct realm_io_pgtable *data)
{
	realm_iopte pte = paddr;

	/* Of the bits which overlap, either 51:48 or 15:12 are always RES0 */
	return (pte | (pte >> (48 - 12))) & REALM_PTE_ADDR_MASK;
}

static void *realm_host_alloc_pages(size_t size, gfp_t gfp,
				    struct io_pgtable_cfg *cfg,
				    void *cookie)
{
	struct device *dev = cfg->iommu_dev;
	int order = get_order(size);
	void *pages;

	if (gfp & __GFP_HIGHMEM)
		return NULL;

	if (cfg->alloc) {
		pages = cfg->alloc(cookie, size, gfp);
	} else {
		struct page *p;

		p = alloc_pages_node(dev_to_node(dev), gfp | __GFP_ZERO, order);
		pages = p ? page_address(p) : NULL;
	}

	if (!pages)
		return NULL;

	return pages;
}

static void realm_host_free_pages(void *pages, size_t size,
				  struct io_pgtable_cfg *cfg,
				  void *cookie)
{
	if (cfg->free)
		cfg->free(cookie, pages, size);
	else
		free_pages((unsigned long)pages, get_order(size));
}

static void realm_sync_pte(realm_iopte *ptep, int num_entries,
			   struct io_pgtable_cfg *cfg)
{
	if (!cfg->coherent_walk)
		dma_sync_single_for_device(cfg->iommu_dev,
					   (dma_addr_t)virt_to_phys(ptep),
					   sizeof(*ptep) * num_entries,
					   DMA_TO_DEVICE);
}

#define MAX_MSI_SUPPROT 64
#define REALM_MSI_IOVA_BASE 0xa004000
#define REALM_MSI_IOVA_OFFSET 4096
#define MSI_IOVA(id) (REALM_MSI_IOVA_BASE + (id) * REALM_MSI_IOVA_OFFSET)

static unsigned long g_msi_addr_slot[MAX_MSI_SUPPROT];
static DEFINE_SPINLOCK(msi_iova_lock);

static unsigned long get_msi_iova(unsigned long paddr, bool need_alloc)
{
	unsigned long msi_addr = 0;
	int i;

	spin_lock(&msi_iova_lock);
	for (i = 0; i < MAX_MSI_SUPPROT; i++) {
		if (g_msi_addr_slot[i] == paddr) {
			msi_addr = MSI_IOVA(i);
			break;
		} else if (g_msi_addr_slot[i] == 0) {
			if (need_alloc) {
				g_msi_addr_slot[i] = paddr;
				msi_addr = MSI_IOVA(i);
			}
			break;
		}
	}
	spin_unlock(&msi_iova_lock);

	return msi_addr;
}

static int realm_mmio_map(struct realm_io_pgtable *data, unsigned long iova,
			  phys_addr_t paddr, size_t size, size_t pgcount,
			  realm_iopte prot, int lvl, realm_iopte *pgd,
			  gfp_t gfp)
{
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	struct realm *realm;
	unsigned long msi_iova;
	int ret;

	if (iova < REALM_MSI_ORIG_IOVA ||
		iova >= REALM_MSI_ORIG_IOVA + MAX_MSI_PAGE * MSI_PAGE_SIZE)
		return 0;

	if (size != SZ_4K || pgcount != 1) {
		pr_err("Bad size of pgcount\n");
		return -EINVAL;
	}

	msi_iova = get_msi_iova(paddr, true);
	if (!msi_iova) {
		pr_err("Bad msi_iova\n");
		return -EINVAL;
	}

	rme_update_msi_iova(cfg->arm_lpae_s2_cfg.vttbr, msi_iova, iova);

	realm = rme_get_realm(cfg->arm_lpae_s2_cfg.vttbr);
	if (!realm)
		return -EINVAL;

	ret = realm_map_mmio_protected(realm, msi_iova, __phys_to_pfn(paddr), size, NULL);
	rme_put_realm(realm);
	if (ret)
		return ret;

	io_pgtable_tlb_flush_walk(&data->iop, msi_iova, size, REALM_GRANULE(data));

	return 0;
}

static void realm_host_init_pte(struct realm_io_pgtable *data,
				phys_addr_t paddr, realm_iopte prot,
				int lvl, int num_entries, realm_iopte *ptep)
{
	realm_iopte pte = prot;
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	size_t sz = REALM_BLOCK_SIZE(lvl, data);
	int i;

	if (data->iop.fmt != ARM_MALI_LPAE && lvl == REALM_MAX_LEVELS - 1)
		pte |= REALM_PTE_TYPE_PAGE;
	else
		pte |= REALM_PTE_TYPE_BLOCK;

	for (i = 0; i < num_entries; i++)
		ptep[i] = pte | paddr_to_iopte(paddr + i * sz, data);

	realm_sync_pte(ptep, num_entries, cfg);
}

static size_t realm_host_unmap(struct realm_io_pgtable *data,
			       struct iommu_iotlb_gather *gather,
			       unsigned long iova, size_t size, size_t pgcount,
			       int lvl, realm_iopte *ptep);

static int realm_init_pte(struct realm_io_pgtable *data,
			  unsigned long iova, phys_addr_t paddr,
			  realm_iopte prot, int lvl, int num_entries,
			  realm_iopte *ptep)
{
	realm_iopte old;
	int i;

	for (i = 0; i < num_entries; i++) {
		old = READ_ONCE(ptep[i]);
		if (iopte_leaf(old, lvl, data->iop.fmt)) {
			/* We require an unmap first */
			return -EEXIST;
		} else if (iopte_type(old) == REALM_PTE_TYPE_TABLE) {
			/*
			 * We need to unmap and free the old table before
			 * overwriting it with a block entry.
			 */
			realm_iopte *tblp;
			size_t sz = REALM_BLOCK_SIZE(lvl, data);

			tblp = ptep - REALM_LVL_IDX(iova, lvl, data);
			if (realm_host_unmap(data, NULL, iova + i * sz, sz, 1,
					     lvl, tblp) != sz) {
				WARN_ON(1);
				return -EINVAL;
			}
		}
	}

	realm_host_init_pte(data, paddr, prot, lvl, num_entries, ptep);
	return 0;
}

static realm_iopte realm_install_table(realm_iopte *table, realm_iopte *ptep,
				       realm_iopte curr,
				       struct realm_io_pgtable *data)
{
	realm_iopte old, new;

	new = paddr_to_iopte(__pa(table), data) | REALM_PTE_TYPE_TABLE;
	/*
	 * Ensure the table itself is visible before its PTE can be.
	 * Whilst we could get away with cmpxchg64_release below, this
	 * doesn't have any ordering semantics when !CONFIG_SMP.
	 */
	dma_wmb();

	old = cmpxchg64_relaxed(ptep, curr, new);

	return old;
}

static int realm_host_map(struct realm_io_pgtable *data, unsigned long iova,
			  phys_addr_t paddr, size_t size, size_t pgcount,
			  realm_iopte prot, int lvl, realm_iopte *ptep,
			  gfp_t gfp, size_t *mapped)
{
	realm_iopte *cptep, pte;
	size_t block_size = REALM_BLOCK_SIZE(lvl, data);
	size_t tblsz = REALM_GRANULE(data);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	int ret = 0, num_entries, max_entries, map_idx_start;

	/* Find our entry at the current level */
	map_idx_start = REALM_LVL_IDX(iova, lvl, data);
	ptep += map_idx_start;

	/* If we can install a leaf entry at this level, then do so */
	if (size == block_size) {
		max_entries = REALM_PTES_PER_TABLE(data) - map_idx_start;
		num_entries = min_t(int, pgcount, max_entries);
		ret = realm_init_pte(data, iova, paddr, prot, lvl, num_entries, ptep);
		if (!ret)
			*mapped += num_entries * size;

		return ret;
	}

	/* We can't allocate tables at the final level */
	if (WARN_ON(lvl >= REALM_MAX_LEVELS - 1))
		return -EINVAL;

	/* Grab a pointer to the next level */
	pte = READ_ONCE(*ptep);
	if (!pte) {
		cptep = realm_host_alloc_pages(tblsz, gfp, cfg, data->iop.cookie);
		if (!cptep)
			return -ENOMEM;

		pte = realm_install_table(cptep, ptep, 0, data);
		if (pte)
			realm_host_free_pages(cptep, tblsz, cfg, data->iop.cookie);

#ifdef CONFIG_HISILICON_ERRATUM_162100602
		if (lvl <= 2)
			io_pgtable_tlb_flush_walk(&data->iop, iova, 0, REALM_GRANULE(data));
#endif
	}

	if (pte && !iopte_leaf(pte, lvl, data->iop.fmt)) {
		cptep = iopte_deref(pte, data);
	} else if (pte) {
		/* We require an unmap first */
		return -EEXIST;
	}

	/* Rinse, repeat */
	return realm_host_map(data, iova, paddr, size, pgcount, prot, lvl + 1,
			      cptep, gfp, mapped);
}

static void realm_host_free_pgtable(struct realm_io_pgtable *data, int lvl,
				    realm_iopte *ptep)
{
	realm_iopte *start, *end;
	unsigned long table_size;

	if (lvl == data->start_level)
		table_size = REALM_PGD_SIZE(data);
	else
		table_size = REALM_GRANULE(data);

	start = ptep;

	/* Only leaf entries at the last level */
	if (lvl == REALM_MAX_LEVELS - 1)
		end = ptep;
	else
		end = (void *)ptep + table_size;

	while (ptep != end) {
		realm_iopte pte = *ptep++;

		if (!pte || iopte_leaf(pte, lvl, data->iop.fmt))
			continue;

		realm_host_free_pgtable(data, lvl + 1, iopte_deref(pte, data));
	}

	realm_host_free_pages(start, table_size, &data->iop.cfg, data->iop.cookie);
}

static size_t realm_host_unmap(struct realm_io_pgtable *data,
			       struct iommu_iotlb_gather *gather,
			       unsigned long iova, size_t size, size_t pgcount,
			       int lvl, realm_iopte *ptep);

static size_t realm_split_blk_unmap(struct realm_io_pgtable *data,
				    struct iommu_iotlb_gather *gather,
				    unsigned long iova, size_t size,
				    realm_iopte blk_pte, int lvl,
				    realm_iopte *ptep, size_t pgcount)
{
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	realm_iopte pte, *tablep;
	phys_addr_t blk_paddr;
	size_t tablesz = REALM_GRANULE(data);
	size_t split_sz = REALM_BLOCK_SIZE(lvl, data);
	int ptes_per_table = REALM_PTES_PER_TABLE(data);
	int i, unmap_idx_start = -1, num_entries = 0, max_entries;

	if (WARN_ON(lvl == REALM_MAX_LEVELS))
		return 0;

	tablep = realm_host_alloc_pages(tablesz, GFP_ATOMIC, cfg, data->iop.cookie);
	if (!tablep)
		return 0;

	if (size == split_sz) {
		unmap_idx_start = REALM_LVL_IDX(iova, lvl, data);
		max_entries = REALM_PTES_PER_TABLE(data) - unmap_idx_start;
		num_entries = min_t(int, pgcount, max_entries);
	}

	blk_paddr = iopte_to_paddr(blk_pte, data);
	pte = blk_pte & ~(REALM_PTE_ADDR_MASK | REALM_PTE_TYPE_MASK);

	for (i = 0; i < ptes_per_table; i++, blk_paddr += split_sz) {
		if (i >= unmap_idx_start && i < (unmap_idx_start + num_entries))
			continue;

		realm_host_init_pte(data, blk_paddr, pte, lvl, 1, &tablep[i]);
	}

	pte = realm_install_table(tablep, ptep, blk_pte, data);
	if (pte != blk_pte) {
		realm_host_free_pages(tablep, tablesz, cfg, data->iop.cookie);
		if (iopte_type(pte) != REALM_PTE_TYPE_TABLE)
			return 0;

		tablep = iopte_deref(pte, data);
	} else if (unmap_idx_start >= 0) {
		for (i = 0; i < num_entries; i++)
			io_pgtable_tlb_add_page(&data->iop, gather,
						iova + i * size, size);

		return num_entries * size;
	}

	return realm_host_unmap(data, gather, iova, size, pgcount, lvl, tablep);
}

static size_t realm_host_unmap(struct realm_io_pgtable *data,
			       struct iommu_iotlb_gather *gather,
			       unsigned long iova, size_t size, size_t pgcount,
			       int lvl, realm_iopte *ptep)
{
	realm_iopte pte;
	struct io_pgtable *iop = &data->iop;
	int i = 0, num_entries, max_entries, unmap_idx_start;

	/* Something went horribly wrong and we ran out of page table */
	if (WARN_ON(lvl == REALM_MAX_LEVELS))
		return 0;

	unmap_idx_start = REALM_LVL_IDX(iova, lvl, data);
	ptep += unmap_idx_start;
	pte = READ_ONCE(*ptep);
	if (WARN_ON(!pte))
		return 0;

	/* If the size matches this level, we're in the right place */
	if (size == REALM_BLOCK_SIZE(lvl, data)) {
		max_entries = REALM_PTES_PER_TABLE(data) - unmap_idx_start;
		num_entries = min_t(int, pgcount, max_entries);

		while (i < num_entries) {
			pte = READ_ONCE(*ptep);
			if (WARN_ON(!pte))
				break;

			*ptep = 0;
			realm_sync_pte(ptep, 1, &iop->cfg);

			if (!iopte_leaf(pte, lvl, iop->fmt)) {
				/* Also flush any partial walks */
				io_pgtable_tlb_flush_walk(iop, iova + i * size, size,
							  REALM_GRANULE(data));
				realm_host_free_pgtable(data, lvl + 1, iopte_deref(pte, data));
			} else if (!iommu_iotlb_gather_queued(gather)) {
				io_pgtable_tlb_add_page(iop, gather, iova + i * size, size);
			}

			ptep++;
			i++;
		}

		return i * size;
	} else if (iopte_leaf(pte, lvl, iop->fmt)) {
		return realm_split_blk_unmap(data, gather, iova, size, pte,
					     lvl + 1, ptep, pgcount);
	}

	/* Keep on walkin' */
	ptep = iopte_deref(pte, data);
	return realm_host_unmap(data, gather, iova, size, pgcount, lvl + 1, ptep);
}

static void *__realm_alloc_pages(size_t size, gfp_t gfp,
				 struct io_pgtable_cfg *cfg)
{
	struct device *dev = cfg->iommu_dev;
	int order = get_order(size);
	struct page *p;
	void *pages;

	p = alloc_pages_node(dev_to_node(dev), gfp | __GFP_ZERO, order);
	if (unlikely(!p))
		return NULL;

	pages = page_address(p);
	if (granule_delegate_range(virt_to_phys(pages), size)) {
		free_pages((unsigned long)pages, order);
		return NULL;
	}

	return pages;
}

static void __realm_free_pages(void *pages, size_t size,
			       struct io_pgtable_cfg *cfg)
{
	/* If the undelegate fails then leak the pages */
	if (WARN_ON(granule_undelegate_range(virt_to_phys(pages), size)))
		return;

	free_pages((unsigned long)pages, get_order(size));
}

static int realm_ns_map(struct realm_io_pgtable *data, unsigned long iova,
			phys_addr_t paddr, size_t size, size_t pgcount,
			realm_iopte prot, int lvl, realm_iopte *pgd,
			gfp_t gfp, size_t *mapped)
{
	int ret = 0;
	realm_iopte *cptep;
	phys_addr_t phys, tbl_entry;
	size_t page_attr, block_size;
	size_t tblsz = REALM_GRANULE(data);
	unsigned long pgdp = virt_to_phys(pgd), map_cnt;

	if (size > SZ_1G || pgcount > U32_MAX)
		return -EINVAL;

	page_attr = size | (pgcount << 32);

	lvl = rmi_smmu_map(pgdp, iova, paddr, prot, page_attr, &map_cnt);
	if (lvl == REALM_MAX_LEVELS)
		*mapped += map_cnt * size;
	if (lvl < 0)
		return -EINVAL;

	for (; lvl < REALM_MAX_LEVELS; lvl++) {
		block_size = REALM_BLOCK_SIZE(lvl, data);

		/* If we can install a leaf entry at this level, then do so */
		if (size == block_size) {
			lvl = rmi_smmu_map(pgdp, iova, paddr, prot, page_attr, &map_cnt);
			if (lvl == REALM_MAX_LEVELS)
				*mapped += map_cnt * size;
			break;
		}

		/* We can't allocate tables at the final level */
		if (WARN_ON(lvl >= REALM_MAX_LEVELS - 1))
			return -EINVAL;

		cptep = (realm_iopte *)__realm_alloc_pages(tblsz, GFP_KERNEL,
							   &data->iop.cfg);
		if (!cptep)
			return -ENOMEM;

		phys = virt_to_phys(cptep);
		tbl_entry = phys | REALM_PTE_TYPE_TABLE;
		ret = rmi_smmu_page_table_create(pgdp, iova, tbl_entry, tblsz,
						 lvl);
		if (ret) {
			__realm_free_pages(cptep, tblsz, &data->iop.cfg);
			break;
		}
	}

	return ret;
}

static void realm_ns_free_pgtable(struct realm_io_pgtable *data, int lvl,
				  void *va, unsigned long iova)
{
	unsigned long i, entry_num, pte, table_size, next, pa;

	if (lvl == data->start_level)
		table_size = REALM_PGD_SIZE(data);
	else
		table_size = REALM_GRANULE(data);

	entry_num = table_size / sizeof(realm_iopte);
	for (i = 0; i < entry_num; i++) {
		next = iova + (i << REALM_LVL_SHIFT(lvl, data));
		rmi_smmu_read_pte(virt_to_phys(data->ns_pgd), next, lvl, &pte);
		if (!pte || iopte_leaf(pte, lvl, data->iop.fmt))
			continue;

		pa = pte & REALM_PTE_ADDR_MASK;
		realm_ns_free_pgtable(data, lvl + 1, __va(pa), next);
	}
	(void)rmi_smmu_page_table_destroy(virt_to_phys(data->ns_pgd), iova,
					  virt_to_phys(va), table_size, lvl);
	__realm_free_pages(va, table_size, &data->iop.cfg);
}

static size_t realm_ns_unmap(struct realm_io_pgtable *data,
			     struct iommu_iotlb_gather *gather,
			     unsigned long iova, size_t size, size_t pgcount,
			     int lvl, realm_iopte *pgd)
{
	unsigned long map_cnt;

	if (size > SZ_1G || pgcount > U32_MAX)
		return -EINVAL;

	(void)rmi_smmu_map(virt_to_phys(pgd), iova, 0, 0, size | (pgcount << 32),
			   &map_cnt);

	return map_cnt * size;
}

static realm_iopte realm_prot_to_pte(struct realm_io_pgtable *data, int prot)
{
	realm_iopte pte;

	pte = REALM_PTE_HAP_FAULT;
	if (prot & IOMMU_READ)
		pte |= REALM_PTE_HAP_READ;
	if (prot & IOMMU_WRITE)
		pte |= REALM_PTE_HAP_WRITE;

	if (prot & IOMMU_MMIO)
		pte |= REALM_PTE_MEMATTR_DEV;
	else if (prot & IOMMU_CACHE)
		pte |= REALM_PTE_MEMATTR_OIWB;
	else
		pte |= REALM_PTE_MEMATTR_NC;

	if (prot & IOMMU_CACHE)
		pte |= REALM_PTE_SH_IS;

	if (prot & IOMMU_NOEXEC)
		pte |= REALM_PTE_XN;

	pte |= REALM_PTE_AF;

	return pte;
}

static int realm_map_pages(struct io_pgtable_ops *ops, unsigned long iova,
			   phys_addr_t paddr, size_t pgsize, size_t pgcount,
			   int iommu_prot, gfp_t gfp, size_t *mapped)
{
	struct realm_io_pgtable *data = io_pgtable_ops_to_data(ops);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	int ret, lvl = data->start_level;
	realm_iopte prot;
	long iaext = (s64)iova >> cfg->ias;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize))
		return -EINVAL;

	if (WARN_ON(iaext || paddr >> cfg->oas))
		return -ERANGE;

	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	prot = realm_prot_to_pte(data, iommu_prot);

	ret = realm_host_map(data, iova, paddr, pgsize, pgcount, prot,
				lvl, (realm_iopte *)data->pgd, gfp, mapped);
	if (ret)
		return ret;

	if (!data->ns) {
		ret = realm_mmio_map(data, iova, paddr, pgsize, pgcount, prot, lvl,
				(realm_iopte *)data->pgd, gfp);
		if (ret)
			goto err_unmap_host;
	} else {
		size_t r_mapped = 0;

		ret = realm_ns_map(data, iova, paddr, pgsize, pgcount,
				   prot | REALM_PTE_NS, lvl,
				   (realm_iopte *)data->ns_pgd, gfp, &r_mapped);
		if (ret)
			goto err_unmap_host;

		if (r_mapped != *mapped) {
			ret = -EPERM;
			goto err_unmap_host;
		}
	}

	/*
	 * Synchronise all PTE updates for the new mapping before there's
	 * a chance for anything to kick off a table walk for the new iova.
	 */
	wmb();

	return ret;

err_unmap_host:
	realm_host_unmap(data, NULL, iova, pgsize, pgcount, lvl,
			 (realm_iopte *)data->pgd);
	*mapped = 0;
	return ret;
}

static phys_addr_t realm_iova_to_phys(struct io_pgtable_ops *ops,
				      unsigned long iova)
{
	struct realm_io_pgtable *data = io_pgtable_ops_to_data(ops);
	realm_iopte pte, *ptep = data->pgd;
	int lvl = data->start_level;

	do {
		/* Valid IOPTE pointer? */
		if (!ptep)

			return 0;
		/* Grab the IOPTE we're interested in */
		ptep += REALM_LVL_IDX(iova, lvl, data);
		pte = READ_ONCE(*ptep);

		/* Valid entry? */
		if (!pte)
			return 0;

		/* Leaf entry? */
		if (iopte_leaf(pte, lvl, data->iop.fmt))
			goto found_translation;

		/* Take it to the next level */
		ptep = iopte_deref(pte, data);
	} while (++lvl < REALM_MAX_LEVELS);

	/* Ran out of page tables to walk */
	return 0;

found_translation:
	iova &= (REALM_BLOCK_SIZE(lvl, data) - 1);
	return iopte_to_paddr(pte, data) | iova;
}

static int realm_mmio_unmap(struct io_pgtable_ops *ops,
			    struct realm_io_pgtable *data,
			    struct iommu_iotlb_gather *gather,
			    unsigned long iova, size_t size, size_t pgcount,
			    int lvl, realm_iopte *pgd, phys_addr_t paddr)
{
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	unsigned long rtt_addr, next_addr;
	struct realm *realm;
	u64 msi_iova;
	int ret;

	if (iova < REALM_MSI_ORIG_IOVA ||
		iova >= REALM_MSI_ORIG_IOVA + MAX_MSI_PAGE * MSI_PAGE_SIZE)
		return 0;

	if (size != SZ_4K || pgcount != 1) {
		pr_err("Bad size of pgcount\n");
		return -EINVAL;
	}

	msi_iova = get_msi_iova(paddr, false);
	if (!msi_iova) {
		pr_err("Cannot find msi_iova\n");
		return -EINVAL;
	}

	realm = rme_get_realm(cfg->arm_lpae_s2_cfg.vttbr);
	if (!realm) {
		pr_err("Cannot get realm from vttbr\n");
		return -EINVAL;
	}

	ret = rmi_dev_unmap(virt_to_phys(realm->rd), msi_iova, &rtt_addr, &next_addr);
	rme_put_realm(realm);
	if (ret) {
		pr_err("Destroy iova failed\n");
		return -ENXIO;
	}

	return 0;
}

static size_t realm_unmap_pages(struct io_pgtable_ops *ops, unsigned long iova,
				size_t pgsize, size_t pgcount,
				struct iommu_iotlb_gather *gather)
{
	struct realm_io_pgtable *data = io_pgtable_ops_to_data(ops);
	struct io_pgtable_cfg *cfg = &data->iop.cfg;
	long iaext = (s64)iova >> cfg->ias;
	int sl = data->start_level;
	size_t unmapped, r_unmapped;
	int ret;

	if (WARN_ON(!pgsize || (pgsize & cfg->pgsize_bitmap) != pgsize || !pgcount))
		return 0;

	if (WARN_ON(iaext))
		return 0;

	if (!data->ns) {
		phys_addr_t paddr = realm_iova_to_phys(ops, iova);

		unmapped = realm_host_unmap(data, gather, iova, pgsize, pgcount, sl,
				      (realm_iopte *)data->pgd);

		ret = realm_mmio_unmap(ops, data, gather, iova, pgsize, pgcount, sl,
				(realm_iopte *)data->pgd, paddr);
		if (ret)
			return 0;
	} else {
		unmapped = realm_host_unmap(data, gather, iova, pgsize, pgcount, sl,
				      (realm_iopte *)data->pgd);
		r_unmapped = realm_ns_unmap(data, gather, iova, pgsize, pgcount,
					    sl, (realm_iopte *)data->ns_pgd);
		if (unmapped != r_unmapped)
			return 0;
	}

	return unmapped;
}

static struct realm_io_pgtable *realm_alloc_pgtable(struct io_pgtable_cfg *cfg,
						    bool ns)
{
	struct realm_io_pgtable *data;
	int levels, va_bits, pg_shift;

	cfg->pgsize_bitmap &= SZ_4K | SZ_2M | SZ_1G;

	if (!(cfg->pgsize_bitmap & SZ_4K))
		return NULL;

	if (cfg->ias > REALM_MAX_ADDR_BITS)
		return NULL;

	if (cfg->oas > REALM_MAX_ADDR_BITS)
		return NULL;

	data = kmalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;
	data->ns = ns;

	pg_shift = __ffs(cfg->pgsize_bitmap);
	data->bits_per_level = pg_shift - ilog2(sizeof(realm_iopte));

	va_bits = cfg->ias - pg_shift;
	levels = DIV_ROUND_UP(va_bits, data->bits_per_level);
	data->start_level = REALM_MAX_LEVELS - levels;

	/* Calculate the actual size of our pgd (without concatenation) */
	data->pgd_bits = va_bits - (data->bits_per_level * (levels - 1));

	data->iop.ops = (struct io_pgtable_ops) {
		.map_pages	= realm_map_pages,
		.unmap_pages	= realm_unmap_pages,
		.iova_to_phys	= realm_iova_to_phys,
	};

	return data;
}

static struct io_pgtable *__realm_alloc_pgtable_s2(struct io_pgtable_cfg *cfg,
						   void *cookie, bool ns)
{
	u64 sl;
	struct realm_io_pgtable *data;
	typeof(&cfg->arm_lpae_s2_cfg.vtcr) vtcr = &cfg->arm_lpae_s2_cfg.vtcr;

	data = realm_alloc_pgtable(cfg, ns);
	if (!data)
		return NULL;

	/*
	 * Concatenate PGDs at level 1 if possible in order to reduce
	 * the depth of the stage-2 walk.
	 */
	if (data->start_level == 0) {
		unsigned long pgd_pages;

		pgd_pages = REALM_PGD_SIZE(data) / sizeof(realm_iopte);
		if (pgd_pages <= REALM_S2_MAX_CONCAT_PAGES) {
			data->pgd_bits += data->bits_per_level;
			data->start_level++;
		}
	}

	/* VTCR */
	vtcr->sh = ARM_LPAE_TCR_SH_IS;
	vtcr->irgn = ARM_LPAE_TCR_RGN_WBWA;
	vtcr->orgn = ARM_LPAE_TCR_RGN_WBWA;
	vtcr->tg = ARM_LPAE_TCR_TG0_4K;
	sl = data->start_level + 1;

	switch (cfg->oas) {
	case 32:
		vtcr->ps = ARM_LPAE_TCR_PS_32_BIT;
		break;
	case 36:
		vtcr->ps = ARM_LPAE_TCR_PS_36_BIT;
		break;
	case 40:
		vtcr->ps = ARM_LPAE_TCR_PS_40_BIT;
		break;
	case 42:
		vtcr->ps = ARM_LPAE_TCR_PS_42_BIT;
		break;
	case 44:
		vtcr->ps = ARM_LPAE_TCR_PS_44_BIT;
		break;
	case 48:
		vtcr->ps = ARM_LPAE_TCR_PS_48_BIT;
		break;
	case 52:
		vtcr->ps = ARM_LPAE_TCR_PS_52_BIT;
		break;
	default:
		goto out_free_data;
	}

	vtcr->tsz = 64ULL - cfg->ias;
	vtcr->sl = ~sl & REALM_VTCR_SL0_MASK;

	if (data->ns) {
		data->ns_pgd = __realm_alloc_pages(REALM_PGD_SIZE(data), GFP_KERNEL, cfg);
		if (!data->ns_pgd)
			goto out_free_data;

		if (rmi_smmu_page_table_create(virt_to_phys(data->ns_pgd), 0,
					       virt_to_phys(data->ns_pgd),
					       REALM_PGD_SIZE(data), 0)) {
			__realm_free_pages(data->ns_pgd, REALM_PGD_SIZE(data), cfg);
			goto out_free_data;
		}
		cfg->realm_s2_cfg.ns_vttbr = virt_to_phys(data->ns_pgd);
	}

	/* Ensure the empty pgd is visible before any actual TTBR write */
	wmb();

	data->pgd = realm_host_alloc_pages(REALM_PGD_SIZE(data), GFP_KERNEL,
					   cfg, cookie);
	if (!data->pgd) {
		if (data->ns)
			goto out_free_realm_page;
		goto out_free_data;
	}

	/* TTBR */
	cfg->arm_lpae_s2_cfg.vttbr = virt_to_phys(data->pgd);
	return &data->iop;

out_free_realm_page:
	rmi_smmu_page_table_destroy(virt_to_phys(data->ns_pgd), 0,
				    virt_to_phys(data->ns_pgd),
				    REALM_PGD_SIZE(data), 0);
	__realm_free_pages(data->ns_pgd, REALM_PGD_SIZE(data), cfg);
out_free_data:
	kfree(data);
	return NULL;
}

static void realm_free_pgtable(struct io_pgtable *iop)
{
	struct realm_io_pgtable *data = io_pgtable_to_data(iop);

	if (data->ns)
		realm_ns_free_pgtable(data, data->start_level, data->ns_pgd, 0UL);

	realm_host_free_pgtable(data, data->start_level, data->pgd);

	kfree(data);
}

static struct io_pgtable *
realm_alloc_pgtable_s2(struct io_pgtable_cfg *cfg, void *cookie)
{
	return __realm_alloc_pgtable_s2(cfg, cookie, false);
}

static struct io_pgtable *
realm_ns_alloc_pgtable_s2(struct io_pgtable_cfg *cfg, void *cookie)
{
	return __realm_alloc_pgtable_s2(cfg, cookie, true);
}

struct io_pgtable_init_fns io_pgtable_realm_s2_init_fns = {
	.alloc	= realm_alloc_pgtable_s2,
	.free	= realm_free_pgtable,
};

struct io_pgtable_init_fns io_pgtable_realm_ns_s2_init_fns = {
	.alloc	= realm_ns_alloc_pgtable_s2,
	.free	= realm_free_pgtable,
};
