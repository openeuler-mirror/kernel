// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: IOMMU API for UMMU
 */

#define pr_fmt(fmt) "UMMU: " fmt

#include <linux/bitfield.h>
#include <linux/kvm_host.h>
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/iova.h>
#include <ub/ubfi/ubfi.h>
#include <linux/slab.h>
#include <linux/io-pgtable.h>
#include <ub/ubus/ubus.h>
#include <linux/ummu_core.h>

#include "ummu.h"
#include "flush.h"
#include "interrupt.h"
#include "logic_ummu/logic_ummu.h"
#include "perm_queue.h"
#include "page_table.h"
#include "cfg_table.h"
#include "perm_table.h"
#include "qos.h"
#include "queue.h"
#include "regs.h"
#include "sva.h"
#include "nested.h"
#include "iommu.h"

#define UMMU_CAPS_NUM 7

static bool ummu_capable(struct device *dev, enum iommu_cap cap)
{
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);
	u32 features;

	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return master->ummu->cap.features & UMMU_FEAT_COHERENCY;
	case IOMMU_CAP_NOEXEC:
	case IOMMU_CAP_DEFERRED_FLUSH:
		return true;
	case IOMMU_CAP_DIRTY_TRACKING: {
		features = (UMMU_FEAT_HD | UMMU_FEAT_COHERENCY);
		return (master->ummu->cap.features & features) == features;
	}
	default:
		return false;
	}
}

static void *ummu_hw_info(struct device *dev, u32 *length, u32 *type)
{
	struct ummu_master *master = (struct ummu_master *)dev_iommu_priv_get(dev);
	struct iommu_hw_info_ummu *info;
	u32 __iomem *base_cap;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info)
		return ERR_PTR(-ENOMEM);

	info->iidr = readl_relaxed(master->ummu->base + UMMU_IIDR);
	info->aidr = readl_relaxed(master->ummu->base + UMMU_AIDR);
	base_cap = master->ummu->base + UMMU_CAP0;
	/*
	 * The first-generation UMMU does not expose its capability registers
	 * to userspace: caps[] keeps the zeroed value from kzalloc, which is
	 * the contract the VMM has been adapted to.
	 */
	if (!ummu_first_generation()) {
		for (int i = 0; i < UMMU_CAPS_NUM; i++)
			info->caps[i] = readl_relaxed(base_cap + i);

		/* Mask IOPF capability because nested guests do not support it.*/
		u32p_replace_bits(&info->caps[STALL_CAP], CAP3_STALL_MODE_NOT_SUPPORT,
				  CAP3_STALL_MODEL_MASK);
	}

	*length = sizeof(*info);
	*type = IOMMU_HW_INFO_TYPE_UMMU;

	return info;
}

struct ummu_domain *ummu_domain_alloc_helper(void)
{
	struct ummu_domain *u_domain;

	u_domain = kzalloc(sizeof(*u_domain), GFP_KERNEL);
	if (!u_domain)
		return NULL;

	u_domain->base_domain.tid = UMMU_INVALID_TID;
	u_domain->qid = UMMU_INVALID_QID;
	mutex_init(&u_domain->init_mutex);

	return u_domain;
}

static struct iommu_domain *ummu_domain_alloc(unsigned int type)
{
	struct ummu_domain *u_domain;

	switch (type) {
	case IOMMU_DOMAIN_DMA:
	case IOMMU_DOMAIN_DMA_FQ:
	case IOMMU_DOMAIN_BLOCKED:
	case IOMMU_DOMAIN_UNMANAGED:
	case IOMMU_DOMAIN_IDENTITY:
		u_domain = ummu_domain_alloc_helper();
		if (!u_domain)
			return ERR_PTR(-ENOMEM);
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	return &u_domain->base_domain.domain;
}

static int ummu_set_dirty_tracking(struct iommu_domain *domain, bool enable)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_device *ummu = core_to_ummu_device(
					u_domain->base_domain.core_dev);

	if (!(ummu->cap.features & UMMU_FEAT_HD))
		return -EOPNOTSUPP;

	u_domain->dirty_tracking = enable;
	return 0;
}

static int ummu_read_and_clear_dirty(struct iommu_domain *domain,
					    unsigned long iova, size_t size,
					    unsigned long flags,
					    struct iommu_dirty_bitmap *dirty)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct io_pgtable_ops *ops = u_domain->cfgs.pgtbl_ops;

	if (!ops || !ops->read_and_clear_dirty)
		return -EOPNOTSUPP;

	if (!u_domain->dirty_tracking && dirty->bitmap)
		return -EINVAL;

	return ops->read_and_clear_dirty(ops, iova, size, flags, dirty);
}

static struct iommu_dirty_ops ummu_dirty_ops = {
	.set_dirty_tracking = ummu_set_dirty_tracking,
	.read_and_clear_dirty = ummu_read_and_clear_dirty,
};

static void ummu_domain_free(struct iommu_domain *domain)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_domain_cfgs *cfgs = &u_domain->cfgs;

	free_io_pgtable_ops(cfgs->pgtbl_ops);

	if (cfgs->stage == UMMU_DOMAIN_S1 &&
	    u_domain->base_domain.tid != UMMU_INVALID_TID &&
	    u_domain->base_domain.tid != UMMU_NO_TID)
		ummu_release_domain_mapt_mem(u_domain);

	kfree(u_domain);
}

static void set_dev_tid(struct device *dev, u32 tid)
{
	struct ub_entity *uent;

	if (dev_is_ub(dev)) {
		uent = to_ub_entity(dev);
		uent->tid = tid;
	}
}

static void ummu_detach_dev(struct ummu_device *ummu,
			    struct ummu_master *master)
{
	struct ummu_domain *u_domain;
	struct iommu_domain *domain;
	u32 tid;
	int ret;

	ret = ummu_get_tid(master->dev, NULL, &tid);
	if (ret || tid == UMMU_INVALID_TID)
		return;

	domain = ummu_core_get_domain_by_tid(master->dev, tid);
	if (!domain)
		return;

	domain = iommu_to_agent_domain(domain);
	if (!(domain->type & (__IOMMU_DOMAIN_PAGING | __IOMMU_DOMAIN_PT)))
		return;

	u_domain = to_ummu_domain(domain);

	if (tid != UMMU_NO_TID)
		ummu_device_clear_tct_desc(ummu, u_domain->cfgs.tect_tag, tid);
}

static int ummu_domain_collect_pgtable_passthrough(struct ummu_domain *u_domain)
{
	struct ummu_device *ummu;
	struct ummu_s1_cfg *cfg;
	int ret = 0;
	u32 ias;

	if (!hw_bypass) {
		ret = ummu_identity_pgtbl_init(u_domain);
	} else {
		ummu = core_to_ummu_device(u_domain->base_domain.core_dev);
		cfg = &u_domain->cfgs.s1_cfg;
		ias = (ummu->cap.features & UMMU_FEAT_VAX) ? 52 : 48;
		cfg->tct.tcr0 |= TCT_ENT0_AA64;
		cfg->tct.tcr1 |= FIELD_PREP(TCT_ENT1_SZ, 64ULL - ias);
		cfg->tct.matt_bypass = 1;
	}
	return ret;
}

static int ummu_domain_attach_mapt(struct ummu_domain *u_domain)
{
#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
	struct ummu_device *ummu = core_to_ummu_device(
					u_domain->base_domain.core_dev);
	u32 tid = u_domain->base_domain.tid;
	enum ummu_mapt_mode mode;
	int ret;

	if (u_domain->cfgs.stage != UMMU_DOMAIN_S1)
		return 0;

	if (unlikely(!(ummu->cap.features & UMMU_FEAT_MAPT)))
		return 0;

	if (tid == UMMU_NO_TID)
		return 0;

	mode = ummu_core_get_mapt_mode(&ummu->core_dev, tid);
	if (mode != MAPT_MODE_END) {
		if (ummu->cap.features & UMMU_FEAT_PPLBI)
			u_domain->cfgs.s1_cfg.io_pt_cfg.positive_plbi = 1;
		if (ummu->cap.features & UMMU_FEAT_FREE_BIT)
			u_domain->cfgs.s1_cfg.io_pt_cfg.free_bit = 1;
		u_domain->cfgs.sva_mode = UMMU_MODE_SVA_SEPARATE_PG;
		u_domain->cfgs.s1_cfg.io_pt_cfg.mode = mode;
		u_domain->base_domain.domain.perm_ops = &ummu_sva_perm_ops;
		ret = ummu_init_sva_mapt_context(u_domain, mode);
		if (ret)
			return ret;
	}
	return 0;
#else
	return 0;
#endif
}

static int ummu_domain_context_prepare(struct ummu_domain *u_domain)
{
	struct ummu_device *ummu = core_to_ummu_device(u_domain->base_domain.core_dev);
	int ret;

	if (u_domain->cfgs.stage == UMMU_DOMAIN_S1) {
		if (!(ummu->cap.features & UMMU_FEAT_TRANS_S1))
			return -EOPNOTSUPP;
	} else if (u_domain->cfgs.stage == UMMU_DOMAIN_S2) {
		if (!(ummu->cap.features & UMMU_FEAT_TRANS_S2))
			return -EOPNOTSUPP;
	} else {
		return -EINVAL;
	}

	if (u_domain->base_domain.domain.type != IOMMU_DOMAIN_IDENTITY) {
		ret = ummu_domain_collect_pgtable(u_domain);
		if (ret)
			return ret;

		ret = ummu_domain_attach_mapt(u_domain);
		if (ret)
			goto err_free_pgtbl;
	} else {
		ret = ummu_domain_collect_pgtable_passthrough(u_domain);
		if (ret)
			return ret;
	}

	u_domain->has_cfged = true;
	return 0;

err_free_pgtbl:
	free_io_pgtable_ops(u_domain->cfgs.pgtbl_ops);
	u_domain->cfgs.pgtbl_ops = NULL;
	return ret;
}

static int ummu_domain_context_set(struct ummu_domain *u_domain,
				   struct ummu_master *master)
{
	struct ummu_tecte_data tect_data;
	struct ummu_tcte_data tct_data;
	int ret;

	ret = ummu_set_domain_cfgs_tag(&u_domain->cfgs, master);
	if (ret)
		return ret;

	if (u_domain->cfgs.stage == UMMU_DOMAIN_S1) {
		ummu_build_s1_domain_tcte(u_domain, &tct_data);
		ummu_write_tct_desc(core_to_ummu_device(
				    u_domain->base_domain.core_dev),
				    u_domain->cfgs.tect_tag,
				    u_domain->base_domain.tid,
				    &tct_data);
		set_dev_tid(master->dev, u_domain->base_domain.tid);
	} else {
		ummu_build_s2_domain_tecte(u_domain, &tect_data);
		ummu_device_write_tecte(core_to_ummu_device(
					u_domain->base_domain.core_dev),
					u_domain->cfgs.tect_tag, &tect_data);
	}
	return 0;
}

static struct iommu_domain *ummu_domain_alloc_user(struct device *dev,
				u32 flags, struct iommu_domain *parent,
				struct kvm *kvm,
				const struct iommu_user_data *user_data)
{
	bool nested_parent = flags & IOMMU_HWPT_ALLOC_NEST_PARENT;
	bool dirty_enable = flags & IOMMU_HWPT_ALLOC_DIRTY_TRACKING;
	const struct ummu_capability *cap = ummu_get_cap();
	struct ummu_domain *u_domain;
	int ret;

	if (flags & ~(IOMMU_HWPT_ALLOC_NEST_PARENT |
		      IOMMU_HWPT_ALLOC_DIRTY_TRACKING))
		return (struct iommu_domain *)ERR_PTR(-EOPNOTSUPP);
	if (parent || user_data)
		return (struct iommu_domain *)ERR_PTR(-EINVAL);

	u_domain = ummu_domain_alloc_helper();
	if (!u_domain)
		return (struct iommu_domain *)ERR_PTR(-ENOMEM);

	if (nested_parent) {
		if (!(cap->features & UMMU_FEAT_NESTING)) {
			ret = -EOPNOTSUPP;
			goto exit_free;
		}
		u_domain->cfgs.stage = UMMU_DOMAIN_S2;
		u_domain->cfgs.nested_parent = true;
	}

	u_domain->base_domain.domain.type = IOMMU_DOMAIN_UNMANAGED;
	if (dirty_enable && u_domain->cfgs.stage == UMMU_DOMAIN_S1)
		u_domain->base_domain.domain.dirty_ops = &ummu_dirty_ops;
	return &u_domain->base_domain.domain;

exit_free:
	kfree(u_domain);
	return (struct iommu_domain *)ERR_PTR(ret);
}

static int ummu_domain_prepare_context_user(struct device *dev, int vmid,
				struct ummu_base_domain *base_domain)
{
	struct ummu_master *master = (struct ummu_master *)dev_iommu_priv_get(dev);
	struct ummu_domain *u_domain = to_ummu_domain(&base_domain->domain);
	int ret;

	u_domain->vmid = (u16)vmid;
	ret = ummu_set_domain_cfgs_tag(&u_domain->cfgs, master);
	if (ret)
		return ret;

	ret = ummu_domain_context_prepare(u_domain);
	if (ret) {
		pr_err("prepare user domain ctx failed, ret = %d\n", ret);
		return ret;
	}
	return 0;
}

static int ummu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);
	int ret;

	/* if the pgtable has been set, clean up the data structures */
	ummu_detach_dev(core_to_ummu_device(u_domain->base_domain.core_dev), master);

	guard(mutex)(&u_domain->init_mutex);
	if (!u_domain->has_cfged) {
		ret = ummu_domain_context_prepare(u_domain);
		if (ret) {
			pr_err("prepare domain ctx failed, ret = %d\n", ret);
			return ret;
		}
	}

	return ummu_domain_context_set(u_domain, master);
}

static int ummu_map_pages(struct iommu_domain *domain, unsigned long iova,
			  phys_addr_t paddr, size_t pgsize, size_t pgcount,
			  int prot, gfp_t gfp, size_t *mapped)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct io_pgtable_ops *ops = u_domain->cfgs.pgtbl_ops;
	int ret;

	if (unlikely(!ops || !ops->map_pages))
		return -ENODEV;

	ret = ops->map_pages(ops, iova, paddr, pgsize, pgcount, prot, gfp,
			      mapped);
	if (ret) {
		pr_err("tid %u map_pages failed on instance, ret = %d.\n",
			u_domain->base_domain.tid, ret);
		return ret;
	}
	return 0;
}

static size_t ummu_unmap_pages(struct iommu_domain *domain, unsigned long iova,
			       size_t pgsize, size_t pgcount,
			       struct iommu_iotlb_gather *gather)
{
	struct ummu_domain *u_domain = to_ummu_domain(domain);
	struct io_pgtable_ops *ops = u_domain->cfgs.pgtbl_ops;

	if (unlikely(!ops || !ops->unmap_pages)) {
		pr_err("tid %u unmap pages cannot find valid ops!\n",
			u_domain->base_domain.tid);
		return 0;
	}

	return ops->unmap_pages(ops, iova, pgsize, pgcount, gather);
}

static phys_addr_t ummu_iova_to_phys(struct iommu_domain *domain,
				     dma_addr_t iova)
{
	struct io_pgtable_ops *ops = to_ummu_domain(domain)->cfgs.pgtbl_ops;

	if (!ops || !ops->iova_to_phys)
		return 0;

	return ops->iova_to_phys(ops, iova);
}

static struct iommu_device *ummu_probe_device(struct device *dev)
{
	struct ummu_master *master;
	struct ummu_device *ummu;

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	ummu = (struct ummu_device *)dev_iommu_priv_get(dev);
	master->dev = dev;
	master->ummu = ummu;
	refcount_set(&master->ksva_ref, 1);
	refcount_set(&master->sva_ref, 1);
	kref_init(&master->ref);
	dev_iommu_priv_set(dev, master);
	return &ummu->core_dev.iommu;
}

static void free_ummu_master(struct kref *ref)
{
	struct ummu_master *master = container_of(ref, struct ummu_master, ref);

	set_dev_tid(master->dev, UMMU_INVALID_TID);
	kfree(master);
}

static void ummu_get_master(struct ummu_master *master)
{
	kref_get(&master->ref);
}

static void ummu_put_master(struct ummu_master *master)
{
	kref_put(&master->ref, free_ummu_master);
}

static int ummu_device_probe_master(struct device *dev)
{
	struct ummu_master *master = (struct ummu_master *)dev_iommu_priv_get(dev);

	if (!master)
		return -ENODEV;

	ummu_get_master(master);
	return 0;
}

static void ummu_release_device(struct device *dev)
{
}

static void ummu_device_remove_master(struct ummu_core_device *core_dev,
				      struct device *dev)
{
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);
	struct ummu_device *ummu = core_to_ummu_device(core_dev);

	if (WARN_ON(ummu_master_sva_enabled(master)) && ummu->evtq.iopf) {
		iopf_queue_flush_dev(dev);
		iopf_queue_remove_device(ummu->evtq.iopf, dev);
	}

	ummu_detach_dev(ummu, master);
	WARN_ON(refcount_read(&master->sva_ref) > 1);
	WARN_ON(refcount_read(&master->ksva_ref) > 1);
	ummu_put_master(master);
}

static void ummu_get_resv_regions(struct device *device, struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	region = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH, prot,
					 IOMMU_RESV_SW_MSI, GFP_KERNEL);
	if (!region)
		return;

	list_add_tail(&region->list, head);

	ubrt_iommu_get_resv_regions(device, head);
}

static struct iommu_group *ummu_device_group(struct device *dev)
{
	return generic_device_group(dev);
}

static int ummu_dev_enable_feat(struct device *dev,
				enum iommu_dev_features feat)
{
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);

	if (!master) {
		pr_err("get invalid dev!\n");
		return -ENODEV;
	}

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return ummu_master_enable_iopf(master);
	case IOMMU_DEV_FEAT_SVA:
	case IOMMU_DEV_FEAT_KSVA:
		return ummu_master_enable_sva(master, feat);
	default:
		return -EINVAL;
	}
}

static int ummu_dev_disable_feat(struct device *dev,
				 enum iommu_dev_features feat)
{
	struct ummu_master *master =
		(struct ummu_master *)dev_iommu_priv_get(dev);

	if (!master) {
		pr_err("get invalid dev!\n");
		return -ENODEV;
	}

	switch (feat) {
	case IOMMU_DEV_FEAT_IOPF:
		return ummu_master_disable_iopf(master);
	case IOMMU_DEV_FEAT_SVA:
	case IOMMU_DEV_FEAT_KSVA:
		return ummu_master_disable_sva(master, feat);
	default:
		return -EINVAL;
	}
}

static int ummu_def_domain_type(struct device *dev)
{
#ifdef CONFIG_UB_UMMU_BYPASSDEV
	int ret;

	ret = ummu_bypass_dev_domain_type(dev);
	if (ret)
		return ret;
#endif
	if (!iommu_default_dma_strict())
		return IOMMU_DOMAIN_DMA_FQ;

	return IOMMU_DOMAIN_DMA;
}

static void ummu_remove_dev_pasid(struct device *dev,
			ioasid_t id, struct iommu_domain *domain)
{
	struct ummu_domain *u_domain;
	struct ummu_master *master;

	master = (struct ummu_master *)dev_iommu_priv_get(dev);
	u_domain = to_ummu_domain(domain);

	ummu_sva_domain_remove_tid(u_domain, master, id);
}

const struct iommu_domain_ops default_domain_ops = {
	.attach_dev = ummu_attach_dev,
	.map_pages = ummu_map_pages,
	.unmap_pages = ummu_unmap_pages,
	.flush_iotlb_all = ummu_flush_iotlb_all,
	.iotlb_sync = ummu_iotlb_sync,
	.iova_to_phys = ummu_iova_to_phys,
	.free = ummu_domain_free,
};

struct iommu_ops ummu_iommu_ops = {
	.capable = ummu_capable,
	.hw_info = ummu_hw_info,
	.domain_alloc = ummu_domain_alloc,
	.domain_alloc_user_v2 = ummu_domain_alloc_user,
	.domain_alloc_sva = ummu_domain_alloc_sva,
	.probe_device = ummu_probe_device,
	.release_device = ummu_release_device,
	.device_group = ummu_device_group,
	.get_resv_regions = ummu_get_resv_regions,
	.dev_enable_feat = ummu_dev_enable_feat,
	.dev_disable_feat = ummu_dev_disable_feat,
	.page_response = ummu_page_response,
	.def_domain_type = ummu_def_domain_type,
	.remove_dev_pasid = ummu_remove_dev_pasid,
	.get_group_qos_params = ummu_group_qos_get_mpam,
	.set_group_qos_params = ummu_group_qos_set_mpam,
	.viommu_alloc = ummu_viommu_alloc,
	.default_domain_ops = &default_domain_ops,
	.pgsize_bitmap = -1UL,
	.owner = THIS_MODULE,
};

static int ummu_get_resource(struct ummu_base_domain *base_domain,
			     struct resource_args *args)
{
	struct ummu_domain *u_domain = to_ummu_domain(&base_domain->domain);
	struct ummu_device *ummu = core_to_ummu_device(base_domain->core_dev);
	int ret;

	switch (args->type) {
	case UMMU_BLOCK:
		ret = ummu_alloc_mapt_blk_mem(u_domain, &args->block);
		pr_debug("tid %u alloc mapt block %s!\n",
			 u_domain->base_domain.tid, ret ? "failed" : "successful");
		break;
	case UMMU_QUEUE:
		if (u_domain->qid == UMMU_INVALID_QID) {
			ret = ummu_domain_config_permq(u_domain);
			if (ret)
				return ret;
		}
		ret = ummu_get_permq_resource(ummu, u_domain->qid, &args->queue);
		break;
	case UMMU_TID_RES:
		ret = ummu_get_tid_res(&args->tid_res);
		if (ret)
			return ret;

		args->tid_res.blk_exp_size = ummu_get_mapt_base_blk_size();
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static void ummu_put_resource(struct ummu_base_domain *base_domain,
			      struct resource_args *args)
{
	struct ummu_domain *u_domain = to_ummu_domain(&base_domain->domain);

	switch (args->type) {
	case UMMU_BLOCK:
		ummu_release_mapt_blk_mem(u_domain, &args->block);
		break;
	case UMMU_QUEUE:
		ummu_release_permq_resource(u_domain);
		break;
	default:
		break;
	}
}

static void ummu_cfg_sync(struct ummu_base_domain *base_domain)
{
	struct ummu_domain *u_domain;
	struct ummu_device *ummu;
	u32 tag, tid;

	if (base_domain->domain.type == IOMMU_DOMAIN_NESTED)
		u_domain = to_nested_domain(&base_domain->domain)->s2_parent;
	else
		u_domain = to_ummu_domain(&base_domain->domain);

	ummu = core_to_ummu_device(base_domain->core_dev);
	tag = u_domain->cfgs.tect_tag;
	tid = u_domain->base_domain.tid;
	if (tid == UMMU_INVALID_TID)
		return;

	ummu_sync_tct(ummu, tag, tid, true);
}

static void ummu_cfg_sync_all(struct ummu_base_domain *base_domain)
{
	struct ummu_domain *u_domain;
	struct ummu_device *ummu;
	u32 tag;

	if (base_domain->domain.type == IOMMU_DOMAIN_NESTED)
		u_domain = to_nested_domain(&base_domain->domain)->s2_parent;
	else
		u_domain = to_ummu_domain(&base_domain->domain);

	ummu = core_to_ummu_device(base_domain->core_dev);
	tag = u_domain->cfgs.tect_tag;

	ummu_device_sync_tect(ummu, tag);
}

static void ummu_sync_domain_mapt_cfg(struct ummu_base_domain *src,
					struct ummu_base_domain *dst)
{
	struct ummu_tct_desc *src_tct, *dst_tct;

	src_tct = &to_ummu_domain(&src->domain)->cfgs.s1_cfg.tct;
	dst_tct = &to_ummu_domain(&dst->domain)->cfgs.s1_cfg.tct;
	dst_tct->mapt_mode = src_tct->mapt_mode;
	dst_tct->mapt_en = src_tct->mapt_en;
	dst_tct->token_en = src_tct->token_en;
	dst_tct->mapt_blk_tbl_phys = src_tct->mapt_blk_tbl_phys;
	dst_tct->mapt_blk_phys = src_tct->mapt_blk_phys;
	dst_tct->blk_tbl_size_order = src_tct->blk_tbl_size_order;
	dst_tct->blk_size_order = src_tct->blk_size_order;
}

static int ummu_sync_dom_cfg(struct ummu_base_domain *src,
			     struct ummu_base_domain *dst,
			     enum ummu_dom_cfg_sync_type type)
{
	switch (type) {
	case SYNC_DOMAIN_MAPT_CFG:
		ummu_sync_domain_mapt_cfg(src, dst);
		break;
	case SYNC_TYPE_NONE:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static int ummu_invalidate_cfg(struct ummu_base_domain *base_domain)
{
	ummu_sva_tcte_invalidate(to_ummu_domain(&base_domain->domain));
	return 0;
}

static int ummu_device_get_hw_cap(struct device *dev, u32 *hw_cap)
{
	const struct ummu_capability *cap;
	struct ummu_master *master;
	bool iopf_enabled = true;
	u32 feature = 0;

	if (!hw_cap)
		return -EINVAL;

	if (dev) {
		master = (struct ummu_master *)dev_iommu_priv_get(dev);
		iopf_enabled = ummu_master_iopf_enabled(master);
	}

	cap = ummu_get_cap();
	if (!cap)
		return -ENODEV;

	if (cap->options & UMMU_OPT_DOUBLE_PLBI)
		feature |= HW_CAP_DOUBLE_PLBI;
	if (cap->options & UMMU_OPT_KCMD_PLBI)
		feature |= HW_CAP_KCMD_PLBI;
	if (cap->features & UMMU_FEAT_PPLBI)
		feature |= HW_CAP_PPLBI;
	if (ummu_get_mapt_blk_exp())
		feature |= HW_CAP_EXPAN;
	if (!ummu_sva_separated_enabled() ||
		(iopf_enabled && (cap->features & UMMU_FEAT_STALLS)))
		feature |= HW_CAP_IOPF;
	if (cap->features & UMMU_FEAT_FREE_BIT)
		feature |= HW_CAP_FREE_BIT;

	*hw_cap = feature;

	return 0;
}

static bool ummu_needs_mmu_notifier(struct ummu_base_domain *base_domain)
{
	struct ummu_device *ummu = core_to_ummu_device(base_domain->core_dev);

	return !(ummu->cap.features & UMMU_FEAT_BTM);
}

static void ummu_domain_clear_mapt_cfg(struct ummu_base_domain *base_domain)
{
	struct ummu_tct_desc *tct;

	tct = &to_ummu_domain(&base_domain->domain)->cfgs.s1_cfg.tct;
	tct->mapt_en = 0;
	tct->token_en = 0;
	tct->mapt_blk_tbl_phys = 0;
	tct->mapt_blk_phys = 0;
	tct->blk_tbl_size_order = 0;
	tct->blk_size_order = 0;
}

const struct ummu_core_ops ummu_ops = {
	.cfg_sync_all = ummu_cfg_sync_all,
	.cfg_sync = ummu_cfg_sync,
	.get_resource = ummu_get_resource,
	.put_resource = ummu_put_resource,
	.add_eid = ummu_add_eid,
	.del_eid = ummu_del_eid,
	.invalidate_cfg = ummu_invalidate_cfg,
	.get_hw_cap = ummu_device_get_hw_cap,
	.dev_config = ummu_device_dev_config,
};

const struct ummu_device_helper ummu_helper = {
	.sync_dom_cfg = ummu_sync_dom_cfg,
	.alloc_domain_nested = ummu_viommu_alloc_domain_nested,
	.cache_invalidate_user = ummu_viommu_cache_invalidate_user,
	.sync_iotlb_all = ummu_flush_iotlb_all,
	.mm_arch_inv_secondary_tlbs = ummu_mm_arch_inv_secondary_tlbs,
	.sync_iommu_domain = ummu_sync_iommu_domain,
	.needs_mmu_notifier = ummu_needs_mmu_notifier,
	.iommu_device_probe_master = ummu_device_probe_master,
	.iommu_device_remove_master = ummu_device_remove_master,
	.clear_domain_mapt = ummu_domain_clear_mapt_cfg,
	.prepare_context_user = ummu_domain_prepare_context_user,
	.iommu_dev_set_mpam = ummu_device_set_group_mpam,
	.device_set_config = ummu_device_set_config,
};
