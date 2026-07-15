// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: UMMU Framework's implementations.
 */
#define pr_fmt(fmt) "[logic ummu]: " fmt

#include <linux/kvm_host.h>
#include <uapi/linux/iommufd.h>
#include <linux/device.h>
#include <linux/err.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <ub/ubfi/ubfi.h>
#include <linux/xarray.h>
#include <linux/cleanup.h>
#include <linux/iommufd.h>
#include <linux/ummu_core.h>
#include <linux/mmu_notifier.h>
#include <linux/rwsem.h>
#include <linux/hisi_ummu.h>

#include "../queue.h"
#include "logic_ummu.h"

struct logic_ummu_device {
	struct ummu_core_device core_dev;
	struct ummu_device *agent_device;
	struct list_head dev_list;
	struct mutex dev_mutex;
	u32 ummu_cnt;
};

struct logic_ummu_viommu {
	struct iommufd_viommu viommu;
	struct ummu_core_device *core_dev;
	struct iommu_domain *parent;
	struct iommu_domain *nested;
};

struct logic_ummu_domain {
	struct ummu_base_domain base_domain;
	struct ummu_base_domain *agent_domain;
	struct logic_ummu_viommu *logic_viommu;
	struct list_head list;
};

struct logic_ummu_mn {
	struct mmu_notifier mmu_notifier;
	struct rw_semaphore rwsem;
	struct list_head list;
};

struct eid_info {
	enum eid_type type;
	eid_t eid;
	guid_t guid;
	struct list_head list;
};

struct logic_ummu_identity_device {
	struct platform_device *pdev;
	u32 tid;
	refcount_t refcount;
};

struct support_cb {
	tdev_select_logic_ummu func;
	struct list_head node;
};

static struct logic_ummu_identity_device *logic_identity_dev;

static DEFINE_SPINLOCK(support_cb_list_lock);
static LIST_HEAD(support_cb_list_head);
static DEFINE_SPINLOCK(eid_list_lock);
static LIST_HEAD(cached_eid_list);
static DEFINE_XARRAY(logic_ummu_ops_info);
static DEFINE_XARRAY(mmu_notifier_xa);
static u32 global_ummu_cnt;
static struct logic_ummu_device logic_ummu;
static struct platform_device *logic_ummu_dev;
const struct fwnode_operations logic_ummu_static_fwnode_ops;
static struct fwnode_handle *logic_ummu_fwnode;

static void gen_iommu_domain_ops(const struct iommu_domain_ops *src, struct iommu_domain_ops *dst);
static void gen_iommu_ops(const struct iommu_ops *src, struct iommu_ops *dst);
static void logic_identity_dev_free(void);
static int logic_domain_set_ops(struct logic_ummu_domain *logic_domain);

static inline struct logic_ummu_domain *
base_to_logic_domain(struct ummu_base_domain *dom)
{
	return container_of(dom, struct logic_ummu_domain, base_domain);
}

static inline struct logic_ummu_domain *
iommu_to_logic_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_domain;

	base_domain = container_of(dom, struct ummu_base_domain, domain);
	return base_to_logic_domain(base_domain);
}

struct iommu_domain *iommu_to_agent_domain(struct iommu_domain *dom)
{
	struct ummu_base_domain *base_domain, *agent_domain;

	base_domain = container_of(dom, struct ummu_base_domain, domain);
	agent_domain = base_to_logic_domain(base_domain)->agent_domain;
	return &agent_domain->domain;
}

static inline const struct iommu_ops *get_agent_iommu_ops(void)
{
	if (!logic_ummu.agent_device)
		return NULL;

	return logic_ummu.agent_device->core_dev.iommu.ops;
}

static inline const struct ummu_core_ops *get_agent_core_ops(void)
{
	if (!logic_ummu.agent_device)
		return NULL;

	return logic_ummu.agent_device->core_dev.ops;
}

static inline const struct ummu_device_helper *get_agent_helper(void)
{
	if (!logic_ummu.agent_device)
		return NULL;

	return logic_ummu.agent_device->helper_ops;
}

static int logic_identity_dev_init(u32 min_pasids, u32 max_pasids)
{
	struct ummu_tid_param tid_para = { .mode = MAPT_MODE_END, .assign_tid = UMMU_INVALID_TID };
	struct dev_iommu *param;
	int ret;

	logic_identity_dev = kzalloc(sizeof(*logic_identity_dev), GFP_KERNEL);
	if (!logic_identity_dev)
		return -ENOMEM;

	logic_identity_dev->pdev =
		platform_device_alloc("identity_dev", PLATFORM_DEVID_NONE);
	if (!logic_identity_dev->pdev) {
		ret = -ENODEV;
		goto err_free;
	}

	param = kzalloc(sizeof(*param), GFP_KERNEL);
	if (!param) {
		ret = -ENOMEM;
		goto err_out;
	}

	param->max_pasids = max_pasids;
	param->min_pasids = min_pasids;
	logic_identity_dev->pdev->dev.iommu = param;

	tid_para.device = &logic_identity_dev->pdev->dev;
	tid_para.domain_type = IOMMU_DOMAIN_IDENTITY;
	tid_para.alloc_mode = TID_ALLOC_NORMAL;
	ret = ummu_core_alloc_tid(&logic_ummu.agent_device->core_dev, &tid_para,
				  &logic_identity_dev->tid);
	if (ret)
		goto err_tid_out;

	refcount_set(&logic_identity_dev->refcount, 1);
	return 0;

err_tid_out:
	kfree(param);
err_out:
	platform_device_put(logic_identity_dev->pdev);
err_free:
	kfree(logic_identity_dev);
	logic_identity_dev = NULL;
	return ret;
}

static void logic_identity_dev_get(struct logic_ummu_identity_device *i_dev)
{
	refcount_inc(&i_dev->refcount);
}

static void logic_identity_dev_put(struct logic_ummu_identity_device *i_dev)
{
	refcount_dec(&i_dev->refcount);
	if (refcount_read(&i_dev->refcount) == 1)
		logic_identity_dev_free();
}

static void logic_domain_update_attr(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *agent = &logic_domain->agent_domain->domain;
	struct iommu_domain *logic = &logic_domain->base_domain.domain;

	logic->pgsize_bitmap = agent->pgsize_bitmap;
	memcpy(&logic->geometry, &agent->geometry, sizeof(logic->geometry));
	logic_domain->base_domain.tid = logic_domain->agent_domain->tid;
}

static int logic_ummu_attach_dev(struct iommu_domain *domain,
				 struct device *dev)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(domain);
	const struct ummu_device_helper *helper = get_agent_helper();
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain, *agent_domain;
	enum ummu_dom_cfg_sync_type sync_type = SYNC_TYPE_NONE;
	const struct iommu_domain_ops *ops;
	int ret;

	agent_domain = logic_domain->agent_domain;
	if (!agent_domain) {
		pr_err("find ummu agent domain failed.\n");
		return -EINVAL;
	}
	ops = agent_domain->domain.ops;
	if (!ops || !ops->attach_dev) {
		pr_err("get ops failed.\n");
		return -ENODEV;
	}

	ret = ops->attach_dev(&agent_domain->domain, dev);
	if (ret) {
		pr_err("attach device failed.\n");
		return ret;
	}
	/* the domain attributes might be changed, sync to logic domain */
	logic_domain_update_attr(logic_domain);
	logic_domain_set_ops(logic_domain);
	if (domain->type != IOMMU_DOMAIN_NESTED)
		sync_type = SYNC_DOM_MUTI_CFG;

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
		if (ummu_base_domain == agent_domain)
			continue;
		if (helper && helper->sync_dom_cfg)
			WARN_ON(helper->sync_dom_cfg(agent_domain, ummu_base_domain, sync_type));
		if (core_ops && core_ops->cfg_sync)
			core_ops->cfg_sync(ummu_base_domain);
	}

	return ret;
}

#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
static int logic_ummu_set_dev_pasid(struct iommu_domain *domain, struct device *dev, ioasid_t pasid)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(domain);
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain, *agent_domain;
	struct ummu_tid_param tid_param = { .mode = MAPT_MODE_END };
	struct ummu_device *agent_ummu = logic_ummu.agent_device;
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_param *param;
	u32 tid;
	int ret;

	agent_domain = logic_domain->agent_domain;
	if (!agent_domain || !agent_ummu)
		return -ENODEV;
	param = (struct ummu_param *)domain->sva_data;
	/* ksva mode must set the param */
	if (!param && iommu_is_ksva_domain(domain))
		return -EINVAL;
	if (param)
		tid_param.mode = param->mode;
	tid_param.device = dev;
	/* allocate a tid equaled pasid. */
	tid_param.assign_tid = pasid;
	tid_param.domain_type = IOMMU_DOMAIN_SVA;
	tid_param.alloc_mode = TID_ALLOC_TRANSPARENT;
	tid_param.mm = domain->mm;
	ret = ummu_core_alloc_tid(&agent_ummu->core_dev, &tid_param, &tid);
	if (ret)
		return ret;
	agent_domain->domain.mm = domain->mm;
	agent_domain->domain.isolated_pasid = domain->isolated_pasid;
	agent_domain->tid = logic_domain->base_domain.tid = tid;
	ret = agent_domain->domain.ops->set_dev_pasid(&agent_domain->domain, dev, tid);
	if (ret)
		goto out_free_tid;

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
		if (ummu_base_domain == agent_domain)
			continue;
		ummu_base_domain->domain.mm = domain->mm;
		ummu_base_domain->domain.isolated_pasid = domain->isolated_pasid;
		if (helper && helper->sync_dom_cfg)
			WARN_ON(helper->sync_dom_cfg(agent_domain, ummu_base_domain,
						     SYNC_DOM_ALL_CFG));
		if (core_ops && core_ops->cfg_sync)
			core_ops->cfg_sync(ummu_base_domain);
	}

	return ret;
out_free_tid:
	ummu_core_free_tid(&agent_ummu->core_dev, tid);
	return ret;
}
#endif

static int logic_ummu_map_pages(struct iommu_domain *domain, unsigned long iova,
				phys_addr_t paddr, size_t pgsize,
				size_t pgcount, int prot, gfp_t gfp,
				size_t *mapped)
{
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;

	agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	ops = agent_domain->domain.ops;

	return ops->map_pages(&agent_domain->domain, iova, paddr, pgsize,
			      pgcount, prot, gfp, mapped);
}

static size_t logic_ummu_unmap_pages(struct iommu_domain *domain,
				     unsigned long iova, size_t pgsize,
				     size_t pgcount,
				     struct iommu_iotlb_gather *gather)
{
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;

	agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	ops = agent_domain->domain.ops;

	return ops->unmap_pages(&agent_domain->domain, iova, pgsize, pgcount, gather);
}

static void logic_ummu_flush_iotlb_all(struct iommu_domain *domain)
{
	struct ummu_base_domain *base_domain, *agent_domain;
	struct logic_ummu_domain *logic_domain;
	const struct iommu_domain_ops *ops;

	logic_domain = iommu_to_logic_domain(domain);
	agent_domain = logic_domain->agent_domain;
	if (!agent_domain) {
		pr_err("flush_iotlb_all: find ummu agent domain failed\n");
		return;
	}
	ops = agent_domain->domain.ops;
	if (!ops || !ops->flush_iotlb_all)
		return;

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list)
		ops->flush_iotlb_all(&base_domain->domain);
}

static void logic_ummu_iotlb_sync(struct iommu_domain *domain,
				  struct iommu_iotlb_gather *gather)
{
	struct ummu_base_domain *base_domain, *agent_domain;
	struct logic_ummu_domain *logic_domain;
	const struct iommu_domain_ops *ops;

	logic_domain = iommu_to_logic_domain(domain);
	agent_domain = logic_domain->agent_domain;
	if (!agent_domain) {
		pr_err("iotlb_sync: find ummu agent domain failed\n");
		return;
	}
	ops = agent_domain->domain.ops;
	if (!ops || !ops->iotlb_sync)
		return;

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list)
		ops->iotlb_sync(&base_domain->domain, gather);
}

static phys_addr_t logic_ummu_iova_to_phys(struct iommu_domain *domain, dma_addr_t iova)
{
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;

	agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	if (!agent_domain) {
		pr_err("find ummu agent domain failed.\n");
		return 0;
	}
	ops = agent_domain->domain.ops;
	if (!ops || !ops->iova_to_phys) {
		pr_err("unsupport ops.\n");
		return 0;
	}

	return ops->iova_to_phys(&agent_domain->domain, iova);
}

static bool logic_ummu_enforce_cache_coherency(struct iommu_domain *domain)
{
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;

	agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	if (!agent_domain) {
		pr_err("find ummu agent domain failed.\n");
		return false;
	}
	ops = agent_domain->domain.ops;
	if (!ops || !ops->enforce_cache_coherency) {
		pr_err("unsupport ops.\n");
		return false;
	}

	return ops->enforce_cache_coherency(&agent_domain->domain);
}

static void logic_domain_free(struct logic_ummu_domain *logic_domain,
			      const struct iommu_domain_ops *domain_ops)
{
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_base_domain *base_domain, *next;

	if (!helper || !helper->sync_dom_cfg) {
		pr_err("invalid ops.\n");
		return;
	}
	list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list) {
		list_del(&base_domain->list);
		if (base_domain != logic_domain->agent_domain) {
			if (domain_ops->flush_iotlb_all)
				domain_ops->flush_iotlb_all(&base_domain->domain);

			helper->sync_dom_cfg(NULL, base_domain, SYNC_CLEAR_DOM_ALL_CFG);
		}
		domain_ops->free(&base_domain->domain);
	}
}

static void logic_nested_domain_free(struct logic_ummu_domain *logic_domain,
				     const struct iommu_domain_ops *domain_ops)
{
	struct ummu_base_domain *nested_base_domain, *nested_iter;

	list_for_each_entry_safe(nested_base_domain, nested_iter,
				 &logic_domain->base_domain.list, list) {
		list_del(&nested_base_domain->list);
		domain_ops->free(&nested_base_domain->domain);
	}
}

static void logic_ummu_mmu_notifier_list_del(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *domain = &logic_domain->base_domain.domain;
	struct logic_ummu_mn *logic_mn;

	logic_mn = xa_load(&mmu_notifier_xa, (u64)(domain->mm));
	if (logic_mn) {
		down_write(&logic_mn->rwsem);
		list_del(&logic_domain->list);
		if (list_empty(&logic_mn->list)) {
			xa_erase(&mmu_notifier_xa, (u64)(domain->mm));
			mmu_notifier_put(&logic_mn->mmu_notifier);
		}
		up_write(&logic_mn->rwsem);
	}
}

static void logic_ummu_free(struct iommu_domain *domain)
{
	struct logic_ummu_domain *logic_domain;
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;

	logic_domain = iommu_to_logic_domain(domain);

	agent_domain = logic_domain->agent_domain;
	if (!agent_domain) {
		pr_err("find ummu agent domain failed.\n");
		return;
	}

	if ((domain->type == IOMMU_DOMAIN_SVA) && !iommu_is_ksva_domain(domain))
		logic_ummu_mmu_notifier_list_del(logic_domain);

	ops = agent_domain->domain.ops;
	if (!ops || !ops->free) {
		pr_err("unsupport ops.\n");
		return;
	}

	if (domain->type != IOMMU_DOMAIN_NESTED) {
		logic_domain_free(logic_domain, ops);
	} else {
		logic_nested_domain_free(logic_domain, ops);
		logic_domain->logic_viommu->nested = NULL;
	}

	kfree(logic_domain);
}

static struct iommu_domain *
logic_ummu_get_msi_mapping_domain(struct iommu_domain *domain)
{
	struct ummu_base_domain *agent_domain;
	const struct iommu_domain_ops *ops;
	struct iommu_domain *parent;

	agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	if (!agent_domain) {
		pr_err("find agent domain failed.\n");
		return NULL;
	}
	ops = agent_domain->domain.ops;
	if (agent_domain->domain.type == IOMMU_DOMAIN_NESTED && ops &&
	    ops->get_msi_mapping_domain) {
		/* this function return s2_domain agent.
		 * here, just check whether the s2_domain
		 * in nested domain is valid.
		 */
		parent = ops->get_msi_mapping_domain(&agent_domain->domain);
		if (parent)
			return agent_domain->parent;
	}
	return NULL;
}

static bool logic_ummu_capable(struct device *dev, enum iommu_cap cap)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->capable) {
		pr_err("unsupport ops.\n");
		return false;
	}

	return ops->capable(dev, cap);
}

static void *logic_ummu_hw_info(struct device *dev, u32 *length, u32 *type)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->hw_info) {
		pr_err("unsupport ops.\n");
		return NULL;
	}

	return ops->hw_info(dev, length, type);
}

#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
static void logic_ummu_plb_sync(struct iommu_domain *d, struct iommu_plb_gather *plb_gather);
static int logic_ummu_grant(struct iommu_domain *d, void *va, size_t size,
			    int perm, void *cookie,
			    struct iommu_plb_gather *plb_gather)
{
	struct ummu_plbi_gather ummu_gather = {.cookie = cookie, .data_cnt = 0};
	struct ummu_base_domain *agent_domain = iommu_to_logic_domain(d)->agent_domain;
	struct iommu_plb_gather local_plb_gather = {};
	const struct iommu_perm_ops *perm_ops;
	int ret;

	if (!agent_domain) {
		pr_err("find agent domain failed.\n");
		return -EINVAL;
	}
	perm_ops = agent_domain->domain.perm_ops;
	if (!perm_ops || !perm_ops->grant) {
		pr_err("unsupport ops.\n");
		return -EOPNOTSUPP;
	}
	ret = perm_ops->grant(&agent_domain->domain, va, size, perm, (void *)&ummu_gather,
			      plb_gather);
	if (ret || !ummu_gather.data_cnt)
		return ret;

	for (u32 idx = 0; idx < ummu_gather.data_cnt; idx++) {
		switch (ummu_gather.plbis[idx].opcode) {
		case CMD_PLBI_OS_VA:
			local_plb_gather.va = (void *)ummu_gather.plbis[idx].plbi_va.va;
			local_plb_gather.size = ummu_gather.plbis[idx].plbi_va.size;
			logic_ummu_plb_sync(d, &local_plb_gather);
			break;
		case CMD_PLBI_OS_N:
			logic_ummu_plbi_free_bit(d, ummu_gather.plbis[idx].plbi_f_bit.lvl_idx,
						 ummu_gather.plbis[idx].plbi_f_bit.lvl_offset);
			break;
		default:
			pr_warn("wrong cmd op code in logic grant.\n");
			break;
		}
	}

	return 0;
}

static int logic_ummu_ungrant(struct iommu_domain *d, void *va, size_t size,
			      void *cookie, struct iommu_plb_gather *plb_gather)
{
	struct ummu_plbi_gather ummu_gather = {.cookie = cookie, .data_cnt = 0};
	struct ummu_base_domain *agent_domain = iommu_to_logic_domain(d)->agent_domain;
	struct iommu_plb_gather local_plb_gather = {};
	const struct iommu_perm_ops *perm_ops;
	int ret;

	if (!agent_domain) {
		pr_err("find agent domain failed.\n");
		return -EINVAL;
	}
	perm_ops = agent_domain->domain.perm_ops;
	if (!perm_ops || !perm_ops->ungrant) {
		pr_err("unsupport ops.\n");
		return -EOPNOTSUPP;
	}
	ret = perm_ops->ungrant(&agent_domain->domain, va, size, (void *)&ummu_gather, plb_gather);
	if (ret || !ummu_gather.data_cnt)
		return ret;

	for (u32 idx = 0; idx < ummu_gather.data_cnt; idx++) {
		switch (ummu_gather.plbis[idx].opcode) {
		case CMD_PLBI_OS_VA:
			local_plb_gather.va = (void *)ummu_gather.plbis[idx].plbi_va.va;
			local_plb_gather.size = ummu_gather.plbis[idx].plbi_va.size;
			logic_ummu_plb_sync(d, &local_plb_gather);
			break;
		case CMD_PLBI_OS_N:
			logic_ummu_plbi_free_bit(d, ummu_gather.plbis[idx].plbi_f_bit.lvl_idx,
						 ummu_gather.plbis[idx].plbi_f_bit.lvl_offset);
			break;
		default:
			pr_warn("wrong cmd op code in logic ungrant.\n");
			break;
		}
	}

	return 0;
}

static void logic_ummu_plb_sync_all(struct iommu_domain *d)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(d);
	struct ummu_base_domain *ummu_base_domain;
	const struct iommu_perm_ops *perm_ops;

	if (!logic_domain->agent_domain) {
		pr_err("find agent domain failed.\n");
		return;
	}
	perm_ops = logic_domain->agent_domain->domain.perm_ops;
	if (!perm_ops || !perm_ops->plb_sync_all) {
		pr_err("unsupport ops.\n");
		return;
	}

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list)
		perm_ops->plb_sync_all(&ummu_base_domain->domain);
}

static void logic_ummu_plb_sync(struct iommu_domain *d, struct iommu_plb_gather *plb_gather)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(d);
	struct ummu_base_domain *base_domain;
	const struct iommu_perm_ops *perm_ops;

	if (!logic_domain->agent_domain) {
		pr_err("find agent domain failed.\n");
		return;
	}
	perm_ops = logic_domain->agent_domain->domain.perm_ops;
	if (!perm_ops || !perm_ops->plb_sync) {
		pr_err("unsupport ops.\n");
		return;
	}

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list)
		perm_ops->plb_sync(&base_domain->domain, plb_gather);
}
#endif

static int logic_ummu_set_dirty_tracking(struct iommu_domain *domain, bool enable)
{
	struct ummu_base_domain *agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	const struct iommu_dirty_ops *ops;

	if (!agent_domain) {
		pr_err("find agent domain failed.\n");
		return -EINVAL;
	}
	ops = agent_domain->domain.dirty_ops;
	if (!ops || !ops->set_dirty_tracking) {
		pr_err("invalid ops.\n");
		return -EOPNOTSUPP;
	}

	return ops->set_dirty_tracking(&agent_domain->domain, enable);
}

static int logic_ummu_read_and_clear_dirty(struct iommu_domain *domain,
					   unsigned long iova, size_t size,
					   unsigned long flags,
					   struct iommu_dirty_bitmap *dirty)
{
	struct ummu_base_domain *agent_domain = iommu_to_logic_domain(domain)->agent_domain;
	const struct iommu_dirty_ops *ops;

	if (!agent_domain) {
		pr_err("find agent domain failed.\n");
		return -EINVAL;
	}
	ops = agent_domain->domain.dirty_ops;
	if (!ops || !ops->read_and_clear_dirty) {
		pr_err("invalid ops.\n");
		return -EOPNOTSUPP;
	}

	return ops->read_and_clear_dirty(&agent_domain->domain, iova, size, flags, dirty);
}

static int logic_domain_set_domain_ops(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *agent_domain = &logic_domain->agent_domain->domain;
	struct iommu_domain_ops *domain_ops;
	int ret;

	domain_ops = (struct iommu_domain_ops *)xa_load(
		&logic_ummu_ops_info, (uintptr_t)agent_domain->ops);
	if (!domain_ops) {
		domain_ops = kzalloc(sizeof(*domain_ops), GFP_KERNEL);
		if (!domain_ops)
			return -ENOMEM;

		gen_iommu_domain_ops(agent_domain->ops, domain_ops);
		ret = xa_err(xa_store(&logic_ummu_ops_info, (uintptr_t)agent_domain->ops,
				      domain_ops, GFP_KERNEL));
		if (ret) {
			kfree(domain_ops);
			return ret;
		}
	}
	logic_domain->base_domain.domain.ops = domain_ops;
	return 0;
}

static int logic_domain_set_dirty_ops(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *agent_domain = &logic_domain->agent_domain->domain;
	struct iommu_dirty_ops *dirty_ops;
	int ret;

	dirty_ops = (struct iommu_dirty_ops *)xa_load(
		&logic_ummu_ops_info, (uintptr_t)agent_domain->dirty_ops);
	if (!dirty_ops) {
		dirty_ops = kzalloc(sizeof(*dirty_ops), GFP_KERNEL);
		if (!dirty_ops)
			return -ENOMEM;

		GEN_IOMMU_DIRTY_OPS(agent_domain->dirty_ops, dirty_ops);
		ret = xa_err(xa_store(&logic_ummu_ops_info, (uintptr_t)agent_domain->dirty_ops,
				      dirty_ops, GFP_KERNEL));
		if (ret) {
			kfree(dirty_ops);
			return ret;
		}
	}
	logic_domain->base_domain.domain.dirty_ops = dirty_ops;
	return 0;
}

#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
static int logic_domain_set_perm_ops(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *agent_domain = &logic_domain->agent_domain->domain;
	struct iommu_perm_ops *perm_ops;
	int ret;

	perm_ops = (struct iommu_perm_ops *)xa_load(
		&logic_ummu_ops_info, (uintptr_t)agent_domain->perm_ops);
	if (!perm_ops) {
		perm_ops = kzalloc(sizeof(*perm_ops), GFP_KERNEL);
		if (!perm_ops)
			return -ENOMEM;

		GEN_IOMMU_PERM_OPS(agent_domain->perm_ops, perm_ops);
		ret = xa_err(xa_store(&logic_ummu_ops_info, (uintptr_t)agent_domain->perm_ops,
				      perm_ops, GFP_KERNEL));
		if (ret) {
			kfree(perm_ops);
			return ret;
		}
	}
	logic_domain->base_domain.domain.perm_ops = perm_ops;
	return 0;
}
#endif

/* logic domain ops follow the singleton, don't free ops */
static int logic_domain_set_ops(struct logic_ummu_domain *logic_domain)
{
	struct iommu_domain *agent_domain = &logic_domain->agent_domain->domain;
	int ret;

	/* the agent domain must have domain_ops */
	if (!agent_domain->ops) {
		pr_err("invalid domain, no ops.\n");
		return -EINVAL;
	}
	ret = logic_domain_set_domain_ops(logic_domain);
	if (ret) {
		pr_err("set domain ops failed, ret=%d.\n", ret);
		return ret;
	}
	if (agent_domain->dirty_ops) {
		ret = logic_domain_set_dirty_ops(logic_domain);
		if (ret) {
			pr_err("set dirty ops failed, ret=%d.\n", ret);
			return ret;
		}
	}
#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
	if (agent_domain->perm_ops) {
		ret = logic_domain_set_perm_ops(logic_domain);
		if (ret) {
			pr_err("set perm ops failed, ret=%d.\n", ret);
			return ret;
		}
	}
#endif
	return ret;
}

/*
 * Cloned from the MAX_TLBI_OPS in arch/arm64/include/asm/tlbflush.h, this
 * is used as a threshold to replace per-page TLBI commands to issue in the
 * command queue with an address-space TLBI command, when UMMU w/o a range
 * invalidation feature handles too many per-page TLBI commands, which will
 * otherwise result in a soft lockup.
 */
#define CMDQ_MAX_TLBI_OPS		(1 << (PAGE_SHIFT - 3))

static void logic_ummu_mm_arch_invalidate_secondary_tlbs(struct mmu_notifier *mn,
						struct mm_struct *mm,
						unsigned long start,
						unsigned long end)
{
	const struct ummu_device_helper *helper = get_agent_helper();
	struct logic_ummu_domain *logic_domain;
	struct ummu_base_domain *base_domain;
	struct iommu_iotlb_gather gather = {};
	struct logic_ummu_mn *logic_mn;
	struct ummu_device *agent_ummu;
	size_t size;

	/*
	 * The mm_types defines vm_end as the first byte after the end address,
	 * different from IOMMU subsystem using the last address of an address
	 * range. So do a simple translation here by calculating size correctly.
	 */
	size = end - start;
	logic_mn = container_of(mn, struct logic_ummu_mn, mmu_notifier);

	if (!down_read_trylock(&logic_mn->rwsem))
		return;

	if (list_empty(&logic_mn->list))
		goto unlock;

	logic_domain = list_first_entry(&logic_mn->list, struct logic_ummu_domain, list);
	agent_ummu = logic_ummu.agent_device;

	if (!(agent_ummu->cap.features & UMMU_FEAT_RANGE_INV)) {
		if (size >= CMDQ_MAX_TLBI_OPS * PAGE_SIZE)
			size = 0;
	} else {
		if (size == ULONG_MAX)
			size = 0;
	}

	if (!size) {
		list_for_each_entry(base_domain, &logic_domain->base_domain.list, list)
			helper->sync_iotlb_all_asid(&base_domain->domain);
	} else {
		gather.start = start;
		gather.end = end - 1;
		gather.pgsize = PAGE_SIZE;
		logic_ummu_iotlb_sync(&logic_domain->base_domain.domain, &gather);
	}

unlock:
	up_read(&logic_mn->rwsem);
}

static void logic_ummu_mmu_notifier_free(struct mmu_notifier *mn)
{
	kfree(container_of(mn, struct logic_ummu_mn, mmu_notifier));
}

static const struct mmu_notifier_ops logic_ummu_mmu_notifier_ops = {
	.arch_invalidate_secondary_tlbs	= logic_ummu_mm_arch_invalidate_secondary_tlbs,
	.free_notifier			= logic_ummu_mmu_notifier_free,
};

static int logic_ummu_mmu_notifier_register(struct logic_ummu_domain *logic_domain,
					    struct mm_struct *mm)
{
	struct logic_ummu_mn *logic_mn;
	int ret;

	logic_mn = xa_load(&mmu_notifier_xa, (u64)(mm));
	if (!logic_mn) {
		logic_mn = kzalloc(sizeof(*logic_mn), GFP_KERNEL);
		if (!logic_mn)
			return -ENOMEM;

		init_rwsem(&logic_mn->rwsem);
		INIT_LIST_HEAD(&logic_mn->list);

		logic_mn->mmu_notifier.ops = &logic_ummu_mmu_notifier_ops;
		ret = mmu_notifier_register(&logic_mn->mmu_notifier, mm);
		if (ret) {
			ret = -EFAULT;
			goto mn_error;
		}
		ret = xa_err(xa_store(&mmu_notifier_xa, (u64)(mm), logic_mn, GFP_KERNEL));
		if (ret)
			goto store_mn_error;
	}
	down_write(&logic_mn->rwsem);
	list_add_tail(&logic_domain->list, &logic_mn->list);
	up_write(&logic_mn->rwsem);
	return 0;

store_mn_error:
	mmu_notifier_unregister(&logic_mn->mmu_notifier, mm);
mn_error:
	kfree(logic_mn);
	return ret;
}

static struct iommu_domain *logic_ummu_domain_alloc_sva(struct device *dev, struct mm_struct *mm)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *base_domain, *next;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;
	struct ummu_device *ummu;
	int ret;

	if (!ops || !ops->domain_alloc_sva)
		return ERR_PTR(-EINVAL);

	logic_domain = kzalloc(sizeof(*logic_domain), GFP_KERNEL);
	if (!logic_domain)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&logic_domain->base_domain.list);
	INIT_LIST_HEAD(&logic_domain->list);

	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		domain = ops->domain_alloc_sva(dev, mm);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			goto error_handle;
		}
		base_domain = to_ummu_base_domain(domain);
		base_domain->core_dev = &ummu->core_dev;
		list_add_tail(&base_domain->list,
			      &logic_domain->base_domain.list);
		if (ummu == logic_ummu.agent_device) {
			logic_domain->agent_domain = base_domain;
			logic_domain->base_domain.domain.type = domain->type;
			logic_domain_update_attr(logic_domain);
			ret = logic_domain_set_ops(logic_domain);
			if (ret)
				goto error_handle;
		}
	}

	if (!(logic_ummu.agent_device->cap.features & UMMU_FEAT_BTM) && mm == current->mm) {
		ret = logic_ummu_mmu_notifier_register(logic_domain, mm);
		if (ret)
			goto error_handle;
	}

	return &logic_domain->base_domain.domain;

error_handle:
	list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list) {
		list_del(&base_domain->list);
		base_domain->domain.ops->free(&base_domain->domain);
	}
	kfree(logic_domain);
	return ERR_PTR(ret);
}

static struct iommu_domain *logic_ummu_domain_alloc(unsigned int iommu_domain_type)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *base_domain, *next;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;
	struct ummu_device *ummu;
	int ret;

	if (!ops || !ops->domain_alloc)
		return ERR_PTR(-EOPNOTSUPP);

	logic_domain = kzalloc(sizeof(*logic_domain), GFP_KERNEL);
	if (!logic_domain)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&logic_domain->base_domain.list);
	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		domain = ops->domain_alloc(iommu_domain_type);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			goto error_handle;
		}
		domain->type = iommu_domain_type;
		domain->pgsize_bitmap = ops->pgsize_bitmap;
		if (!domain->ops)
			domain->ops = ops->default_domain_ops;

		/* add ummu hw info to ummu_base_domain */
		base_domain = to_ummu_base_domain(domain);
		base_domain->core_dev = &ummu->core_dev;
		list_add_tail(&base_domain->list, &logic_domain->base_domain.list);
		if (ummu == logic_ummu.agent_device) {
			logic_domain->agent_domain = base_domain;
			logic_domain->base_domain.domain.type = domain->type;
			logic_domain_update_attr(logic_domain);
			ret = logic_domain_set_ops(logic_domain);
			if (ret)
				goto error_handle;
		}
	}
	return &logic_domain->base_domain.domain;
error_handle:
	list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list) {
		list_del(&base_domain->list);
		base_domain->domain.ops->free(&base_domain->domain);
	}
	kfree(logic_domain);
	return ERR_PTR(ret);
}

static struct iommu_domain *
logic_ummu_domain_alloc_user_v2(struct device *dev, u32 flags,
			     struct iommu_domain *parent, struct kvm *kvm,
			     const struct iommu_user_data *data)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *base_domain, *next;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;
	struct ummu_device *ummu;
	int ret;

	if (!ops || !ops->domain_alloc_user_v2)
		return ERR_PTR(-EOPNOTSUPP);
	logic_domain = kzalloc(sizeof(*logic_domain), GFP_KERNEL);
	if (!logic_domain)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&logic_domain->base_domain.list);
	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		domain = ops->domain_alloc_user_v2(dev, flags, parent, kvm, data);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			goto error_handle;
		}
		if (!domain->pgsize_bitmap)
			domain->pgsize_bitmap = ops->pgsize_bitmap;
		if (!domain->ops)
			domain->ops = ops->default_domain_ops;
		base_domain = to_ummu_base_domain(domain);
		base_domain->core_dev = &ummu->core_dev;
		list_add_tail(&base_domain->list, &logic_domain->base_domain.list);
		if (ummu == logic_ummu.agent_device) {
			logic_domain->agent_domain = to_ummu_base_domain(domain);
			logic_domain->base_domain.domain.type = domain->type;
			logic_domain_update_attr(logic_domain);
			ret = logic_domain_set_ops(logic_domain);
			if (ret)
				goto error_handle;
		}
	}
	return &logic_domain->base_domain.domain;
error_handle:
	list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list) {
		list_del(&base_domain->list);
		base_domain->domain.ops->free(&base_domain->domain);
	}
	kfree(logic_domain);
	return ERR_PTR(ret);
}

static struct iommu_domain *
logic_ummu_viommu_alloc_domain_nested(struct iommufd_viommu *viommu,
				      u32 flags,
				      const struct iommu_user_data *user_data)
{
	struct logic_ummu_viommu *logic_vummu = container_of(viommu, struct logic_ummu_viommu,
							     viommu);
	struct logic_ummu_domain *parent_logic_domain, *logic_domain;
	const struct iommu_ops *drv_ops = get_agent_iommu_ops();
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_base_domain *nested_base_domain, *iter;
	struct iommu_domain *domain;
	struct ummu_device *ummu;
	int ret;

	if (!helper || !helper->alloc_domain_nested)
		return ERR_PTR(-EOPNOTSUPP);
	logic_domain = kzalloc(sizeof(*logic_domain), GFP_KERNEL);
	if (!logic_domain)
		return ERR_PTR(-ENOMEM);
	INIT_LIST_HEAD(&logic_domain->base_domain.list);
	parent_logic_domain = iommu_to_logic_domain(logic_vummu->parent);
	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		domain = helper->alloc_domain_nested(&parent_logic_domain->agent_domain->domain,
						     flags, user_data);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			goto error_handle;
		}
		if (!domain->pgsize_bitmap)
			domain->pgsize_bitmap = drv_ops->pgsize_bitmap;
		nested_base_domain = to_ummu_base_domain(domain);
		nested_base_domain->core_dev = &ummu->core_dev;
		nested_base_domain->parent = logic_vummu->parent;
		if (!domain->ops) {
			ret = -EOPNOTSUPP;
			goto error_handle;
		}
		list_add_tail(&nested_base_domain->list, &logic_domain->base_domain.list);
		if (ummu == logic_ummu.agent_device) {
			logic_domain->agent_domain = to_ummu_base_domain(domain);
			logic_domain->base_domain.domain.type = domain->type;
			logic_domain_update_attr(logic_domain);
			ret = logic_domain_set_ops(logic_domain);
			if (ret)
				goto error_handle;
		}
	}
	logic_vummu->nested = &logic_domain->base_domain.domain;
	logic_domain->logic_viommu = logic_vummu;
	return &logic_domain->base_domain.domain;
error_handle:
	list_for_each_entry_safe(nested_base_domain, iter, &logic_domain->base_domain.list, list) {
		list_del(&nested_base_domain->list);
		nested_base_domain->domain.ops->free(&nested_base_domain->domain);
	}
	kfree(logic_domain);
	return ERR_PTR(ret);
}

static int logic_ummu_viommu_cache_invalidate(struct iommufd_viommu *viommu,
					      struct iommu_user_data_array *array)
{
	struct logic_ummu_viommu *logic_vummu =
		container_of(viommu, struct logic_ummu_viommu, viommu);
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_base_domain *nested_base_domain;
	struct logic_ummu_domain *logic_domain;
	u32 cmd_num, succ_cnt;
	int err, ret = 0;

	if (!logic_vummu->nested || !array) {
		pr_debug("invalid viommu.\n");
		return -EINVAL;
	}

	if (!helper || !helper->cache_invalidate_user)
		return -EOPNOTSUPP;

	logic_domain = iommu_to_logic_domain(logic_vummu->nested);
	cmd_num = array->entry_num;
	succ_cnt = array->entry_num;
	list_for_each_entry(nested_base_domain, &logic_domain->base_domain.list, list) {
		err = helper->cache_invalidate_user(&nested_base_domain->domain,
						 array);
		if (err) {
			succ_cnt = (succ_cnt < array->entry_num) ? succ_cnt : array->entry_num;
			array->entry_num = cmd_num;
			ret = err;
		}
	}

	array->entry_num = succ_cnt;
	return ret;
}

static const struct iommufd_viommu_ops logic_ummu_viommu_ops = {
	.alloc_domain_nested = logic_ummu_viommu_alloc_domain_nested,
	.cache_invalidate = logic_ummu_viommu_cache_invalidate,
};

static struct iommufd_viommu *
logic_ummu_viommu_alloc(struct device *dev, struct iommu_domain *parent,
			struct iommufd_ctx *ictx, unsigned int viommu_type)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct logic_ummu_viommu *logic_vummu;

	if (viommu_type != IOMMU_VIOMMU_TYPE_UMMU)
		return ERR_PTR(-EINVAL);

	if (!ops || !ops->viommu_alloc)
		return ERR_PTR(-EOPNOTSUPP);

	/*
	 * ops->viommu_alloc does not do anything, If an operation is added to
	 * the driver in the future, this call needs to be added.
	 */

	logic_vummu = iommufd_viommu_alloc(ictx, struct logic_ummu_viommu,
					   viommu, &logic_ummu_viommu_ops);
	if (IS_ERR(logic_vummu))
		return ERR_CAST(logic_vummu);

	logic_vummu->core_dev = iommu_get_iommu_dev(dev, struct ummu_core_device, iommu);
	logic_vummu->parent = parent;

	return &logic_vummu->viommu;
}

static struct iommu_domain *logic_ummu_domain_alloc_paging(struct device *dev)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->domain_alloc_paging) {
		pr_err("invalid ops.\n");
		return NULL;
	}

	return ops->domain_alloc_paging(dev);
}

static struct iommu_device *logic_ummu_probe_device(struct device *dev)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct iommu_device *ummu;

	if (!ops || !ops->probe_device) {
		pr_err("invalid ops.\n");
		return NULL;
	}

	dev_iommu_priv_set(dev, logic_ummu.agent_device);
	ummu = ops->probe_device(dev);
	if (IS_ERR(ummu)) {
		pr_err("probed device failed.\n");
		dev_iommu_priv_set(dev, NULL);
		return ummu;
	}
	return &logic_ummu.core_dev.iommu;
}

static void logic_ummu_release_device(struct device *dev)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *ummu_base_domain;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;

	if (!ops || !ops->release_device) {
		pr_err("invalid ops.\n");
		return;
	}
	ops->release_device(dev);

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		pr_err("find domain failed.\n");
		return;
	}

	if (domain->type == IOMMU_DOMAIN_IDENTITY && !iommu_default_passthrough() &&
	    logic_identity_dev && !hw_bypass) {
		logic_identity_dev_put(logic_identity_dev);
		return;
	}

	logic_domain = iommu_to_logic_domain(domain);
	if (!logic_domain->agent_domain || !core_ops || !core_ops->cfg_sync) {
		pr_err("invalid params.\n");
		return;
	}

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
		if (ummu_base_domain == logic_domain->agent_domain)
			continue;

		core_ops->cfg_sync(ummu_base_domain);
	}
}

static void logic_ummu_probe_finalize(struct device *dev)
{
	const struct ummu_device_helper *helper = get_agent_helper();
	struct iommu_domain *domain = iommu_get_domain_for_dev(dev);
	struct ummu_base_domain *base_domain, *next;
	struct logic_ummu_domain *logic_domain;

	if (!domain)
		return;

	logic_domain = iommu_to_logic_domain(domain);
	if (!logic_domain)
		return;

	if (helper && helper->sync_iommu_domain)
		list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list)
			helper->sync_iommu_domain(base_domain, domain);
}

static struct iommu_group *logic_ummu_device_group(struct device *dev)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->device_group) {
		pr_err("invalid ops.\n");
		return NULL;
	}

	return ops->device_group(dev);
}

static void logic_ummu_get_resv_regions(struct device *dev, struct list_head *list)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->get_resv_regions) {
		pr_err("invalid ops.\n");
		return;
	}

	ops->get_resv_regions(dev, list);
}

static int logic_ummu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->of_xlate) {
		pr_err("invalid ops.\n");
		return -ENODEV;
	}

	return ops->of_xlate(dev, args);
}

static bool logic_ummu_is_attach_deferred(struct device *dev)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->is_attach_deferred) {
		pr_err("invalid ops.\n");
		return false;
	}

	return ops->is_attach_deferred(dev);
}

static int logic_ummu_dev_enable_feat(struct device *dev, enum iommu_dev_features f)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->dev_enable_feat) {
		pr_err("invalid ops.\n");
		return -ENODEV;
	}

	return ops->dev_enable_feat(dev, f);
}

static int logic_ummu_dev_disable_feat(struct device *dev, enum iommu_dev_features f)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->dev_disable_feat) {
		pr_err("invalid ops.\n");
		return -ENODEV;
	}

	return ops->dev_disable_feat(dev, f);
}

static void logic_ummu_page_response(struct device *dev, struct iopf_fault *evt,
				     struct iommu_page_response *msg)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->page_response) {
		pr_err("invalid ops.\n");
		return;
	}

	ops->page_response(dev, evt, msg);
}

static int logic_ummu_def_domain_type(struct device *dev)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->def_domain_type) {
		pr_err("invalid ops.\n");
		return 0;
	}

	return ops->def_domain_type(dev);
}

#ifdef CONFIG_UB_UMMU_SVA
static void logic_ummu_remove_dev_pasid(struct device *dev, ioasid_t pasid,
					struct iommu_domain *domain)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(domain);
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	const struct ummu_device_helper *helper = get_agent_helper();
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *base_domain;
	u32 tid = pasid;

	if (!ops || !ops->remove_dev_pasid || !helper || !helper->sync_dom_cfg) {
		pr_err("invalid params.\n");
		return;
	}
	if (!logic_domain->agent_domain) {
		pr_err("invalid agent_domain.\n");
		return;
	}
	ops->remove_dev_pasid(dev, tid, &logic_domain->agent_domain->domain);
	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list) {
		base_domain->domain.mm = NULL;
		if (base_domain == logic_domain->agent_domain)
			continue;

		helper->sync_dom_cfg(logic_domain->agent_domain, base_domain, SYNC_DOM_ALL_CFG);

		if (core_ops && core_ops->cfg_sync)
			core_ops->cfg_sync(base_domain);
	}

	iommu_plb_sync_all(domain);
	/* release the tid */
	ummu_core_free_tid(&logic_ummu.core_dev, tid);
}
#endif

static int logic_ummu_set_group_qos_params(struct iommu_group *group, u16 partid, u8 pmg)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *ummu_base_domain;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;
	int ret;

	domain = iommu_get_domain_for_group(group);
	if (!domain)
		return -ENODEV;

	logic_domain = iommu_to_logic_domain(domain);
	if (!logic_domain->agent_domain)
		return -EINVAL;

	ret = ops->set_group_qos_params(group, partid, pmg);
	if (ret)
		return ret;

	if (unlikely(!core_ops || !core_ops->cfg_sync))
		return -EFAULT;

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
		if (ummu_base_domain == logic_domain->agent_domain)
			continue;

		core_ops->cfg_sync(ummu_base_domain);
	}
	return ret;
}

static int logic_ummu_get_group_qos_params(struct iommu_group *group, u16 *partid, u8 *pmg)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();

	if (!ops || !ops->get_group_qos_params) {
		pr_err("invalid iommu ops.\n");
		return -ENODEV;
	}
	return ops->get_group_qos_params(group, partid, pmg);
}

static int logic_ummu_attach_dev_identity(struct iommu_domain *domain, struct device *dev)
{
	const struct ummu_device_helper *helper = get_agent_helper();
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *base_domain, *agent_domain;
	struct logic_ummu_domain *logic_domain;
	const struct iommu_domain_ops *ops;
	struct ummu_core_device *core_dev;
	int ret;

	logic_domain = iommu_to_logic_domain(domain);
	agent_domain = logic_domain->agent_domain;
	ops = agent_domain->domain.ops;
	if (!ops || !ops->attach_dev) {
		pr_err("get ops failed.\n");
		return -ENODEV;
	}

	if (!hw_bypass && !logic_identity_dev) {
		core_dev = agent_domain->core_dev;
		ret = logic_identity_dev_init(core_dev->iommu.min_pasids,
					      core_dev->iommu.max_pasids);
		if (ret) {
			pr_err("init identity device failed, ret = %d\n", ret);
			return ret;
		}
		agent_domain->tid = logic_identity_dev->tid;
	}

	ret = ops->attach_dev(&agent_domain->domain, dev);
	if (ret) {
		pr_err("attach identity device failed.\n");
		return ret;
	}

	logic_domain_update_attr(logic_domain);
	if (!hw_bypass)
		logic_identity_dev_get(logic_identity_dev);

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list) {
		if (base_domain == agent_domain)
			continue;
		if (helper && helper->sync_dom_cfg)
			WARN_ON(helper->sync_dom_cfg(agent_domain, base_domain, SYNC_DOM_MUTI_CFG));
		if (core_ops && core_ops->cfg_sync)
			core_ops->cfg_sync(base_domain);
	}
	return 0;
}

static struct logic_ummu_domain *logic_ummu_identity_dom;

static const struct iommu_domain_ops logic_iommu_identity_ops = {
	.attach_dev = logic_ummu_attach_dev_identity,
};

static void logic_identity_dev_free(void)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *base_domain;

	if (logic_identity_dev && logic_identity_dev->pdev) {
		WARN_ON(refcount_read(&logic_identity_dev->refcount) != 1);
		kfree(logic_identity_dev->pdev->dev.iommu);
		list_for_each_entry(base_domain,
			&logic_ummu_identity_dom->base_domain.list, list) {
			core_ops->cfg_sync(base_domain);
			base_domain->domain.ops->flush_iotlb_all(&base_domain->domain);
		}
		ummu_core_free_tid(&logic_ummu.agent_device->core_dev, logic_identity_dev->tid);
		platform_device_put(logic_identity_dev->pdev);
		kfree(logic_identity_dev);
		logic_identity_dev = NULL;
	}
}

static struct iommu_domain *logic_ummu_domain_alloc_identity(void)
{
	const struct iommu_ops *ops = get_agent_iommu_ops();
	struct ummu_base_domain *base_domain, *next;
	struct iommu_domain *domain;
	struct ummu_device *ummu;
	int ret;

	if (logic_ummu_identity_dom)
		return &logic_ummu_identity_dom->base_domain.domain;

	logic_ummu_identity_dom = kzalloc(sizeof(*logic_ummu_identity_dom), GFP_KERNEL);
	if (!logic_ummu_identity_dom)
		return (struct iommu_domain *)ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&logic_ummu_identity_dom->base_domain.list);

	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		domain = ops->domain_alloc(IOMMU_DOMAIN_IDENTITY);
		if (IS_ERR(domain)) {
			ret = PTR_ERR(domain);
			goto error_handle;
		}

		memcpy(domain, ops->identity_domain, sizeof(struct iommu_domain));

		/* add ummu hw info to ummu_base_domain */
		base_domain = to_ummu_base_domain(domain);
		base_domain->core_dev = &ummu->core_dev;

		list_add_tail(&base_domain->list, &logic_ummu_identity_dom->base_domain.list);
		if (ummu == logic_ummu.agent_device)
			logic_ummu_identity_dom->agent_domain = base_domain;
	}
	logic_ummu_identity_dom->base_domain.domain.ops = &logic_iommu_identity_ops;
	logic_ummu_identity_dom->base_domain.domain.type = IOMMU_DOMAIN_IDENTITY;

	return &logic_ummu_identity_dom->base_domain.domain;
error_handle:
	list_for_each_entry_safe(base_domain, next,
				 &logic_ummu_identity_dom->base_domain.list,
				 list) {
		list_del(&base_domain->list);
		base_domain->domain.ops->free(&base_domain->domain);
	}
	kfree(logic_ummu_identity_dom);
	logic_ummu_identity_dom = NULL;
	return (struct iommu_domain *)ERR_PTR(ret);
}

static void logic_ummu_domain_identity_free(void)
{
	struct ummu_base_domain *base_domain, *next;

	if (!logic_ummu_identity_dom)
		return;

	list_for_each_entry_safe(base_domain, next,
				 &logic_ummu_identity_dom->base_domain.list,
				 list) {
		list_del(&base_domain->list);
		base_domain->domain.ops->free(&base_domain->domain);
	}
	kfree(logic_ummu_identity_dom);
	logic_ummu_identity_dom = NULL;
}

static struct iommu_ops logic_iommu_ops = {
	.pgsize_bitmap = SZ_4K,
	.owner = THIS_MODULE,
};

static u32 get_ummu_count(void)
{
	return ubrt_fwnode_get_count(UBRT_UMMU);
}

static void logic_ummu_cfg_sync_all(struct ummu_base_domain *d)
{
	struct logic_ummu_domain *logic_domain = base_to_logic_domain(d);
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain;

	if (!core_ops || !core_ops->cfg_sync_all) {
		pr_err("invalid core_ops.\n");
		return;
	}
	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list)
		core_ops->cfg_sync_all(ummu_base_domain);
}

static void logic_ummu_cfg_sync(struct ummu_base_domain *d)
{
	struct logic_ummu_domain *logic_domain = base_to_logic_domain(d);
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain;

	if (!core_ops || !core_ops->cfg_sync) {
		pr_err("invalid core_ops.\n");
		return;
	}
	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list)
		core_ops->cfg_sync(ummu_base_domain);
}

static int logic_ummu_get_resource(struct ummu_base_domain *d, struct resource_args *args)
{
	struct logic_ummu_domain *logic_domain = base_to_logic_domain(d);
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct resource_args ummu_args = { .type = UMMU_QUEUE };
	struct ummu_base_domain *entry, *agent_domain;
	int i = 0, j = 0, ret = 0;

	if (!core_ops || !core_ops->get_resource || !core_ops->put_resource)
		return -ENODEV;

	agent_domain = logic_domain->agent_domain;
	if (!agent_domain)
		return -EINVAL;

	switch (args->type) {
	case UMMU_BLOCK:
	case UMMU_TID_RES:
		ret = core_ops->get_resource(agent_domain, args);
		break;
	case UMMU_CNT:
		args->ummu_cnt = logic_ummu.ummu_cnt;
		break;
	case UMMU_QUEUE_LIST:
		ret = -ENODEV;
		list_for_each_entry(entry, &logic_domain->base_domain.list, list) {
			ret = core_ops->get_resource(entry, &ummu_args);
			if (ret)
				goto release_resource;
			args->queues[i].pcmdq_base = ummu_args.queue.pcmdq_base;
			args->queues[i].pcplq_base = ummu_args.queue.pcplq_base;
			args->queues[i].ctrl_page = ummu_args.queue.ctrl_page;
			i++;
		}
		break;
	default:
		ret = -EINVAL;
	}
	return ret;
release_resource:
	list_for_each_entry(entry, &logic_domain->base_domain.list, list) {
		if (j >= i)
			break;
		core_ops->put_resource(entry, &ummu_args);
		j++;
	}
	return ret;
}

static void logic_ummu_put_resource(struct ummu_base_domain *d, struct resource_args *args)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain, *agent_domain;
	struct logic_ummu_domain *logic_domain;
	struct resource_args ummu_args;

	if (!core_ops || !core_ops->put_resource) {
		pr_err("invalid core_ops.\n");
		return;
	}
	logic_domain = base_to_logic_domain(d);
	switch (args->type) {
	case UMMU_BLOCK:
		agent_domain = logic_domain->agent_domain;
		if (!agent_domain) {
			pr_err("invalid agent_domain.\n");
			return;
		}
		core_ops->put_resource(agent_domain, args);
		list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
			if (ummu_base_domain == agent_domain)
				continue;

			if (core_ops->cfg_sync)
				core_ops->cfg_sync(ummu_base_domain);
		}
		break;
	case UMMU_QUEUE_LIST:
		ummu_args.type = UMMU_QUEUE;
		list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list)
			core_ops->put_resource(ummu_base_domain, &ummu_args);
		break;
	default:
		pr_err("undefined resource type = %u.\n", args->type);
	}
}

static bool is_eid_added(eid_t eid)
{
	struct eid_info *info;

	guard(spinlock)(&eid_list_lock);
	list_for_each_entry(info, &cached_eid_list, list) {
		if (info->eid == eid)
			return true;
	}
	return false;
}

static int logic_ummu_add_eid(struct ummu_core_device *device, guid_t *guid,
			      eid_t eid, enum eid_type type)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_device *ummu, *del;
	struct eid_info *info;
	int ret;

	if (!core_ops || !core_ops->add_eid) {
		pr_err("invalid core_ops.\n");
		return -ENODEV;
	}

	/* If the eid has been added, exit directly. */
	if (is_eid_added(eid))
		return -EEXIST;

	info = kzalloc(sizeof(*info), GFP_ATOMIC);
	if (!info)
		return -ENOMEM;

	guard(spinlock)(&eid_list_lock);
	list_for_each_entry(ummu, &logic_ummu.dev_list, list) {
		ret = core_ops->add_eid(&ummu->core_dev, guid, eid, type);
		if (ret)
			goto free;
	}
	info->eid = eid;
	info->type = type;
	guid_copy(&info->guid, guid);
	list_add_tail(&info->list, &cached_eid_list);

	return 0;

free:
	list_for_each_entry(del, &logic_ummu.dev_list, list) {
		if (del == ummu)
			break;
		core_ops->del_eid(&del->core_dev, guid, eid, type);
	}
	kfree(info);
	return ret;
}

static void logic_ummu_del_eid(struct ummu_core_device *device, guid_t *guid,
			       eid_t eid, enum eid_type type)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct eid_info *info, *next;
	struct ummu_device *ummu;

	if (!core_ops || !core_ops->del_eid) {
		pr_err("invalid core_ops.\n");
		return;
	}

	guard(spinlock)(&eid_list_lock);
	list_for_each_entry(ummu, &logic_ummu.dev_list, list)
		core_ops->del_eid(&ummu->core_dev, guid, eid, type);

	list_for_each_entry_safe(info, next, &cached_eid_list, list)
		if (info->eid == eid) {
			list_del(&info->list);
			kfree(info);
			break;
		}
}

static void remove_all_eid(void)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct eid_info *info, *next;
	struct ummu_device *ummu;

	if (!core_ops || !core_ops->del_eid) {
		pr_err("invalid core_ops.\n");
		return;
	}
	guard(spinlock)(&eid_list_lock);

	list_for_each_entry_safe(info, next, &cached_eid_list, list) {
		list_for_each_entry(ummu, &logic_ummu.dev_list, list)
			core_ops->del_eid(&ummu->core_dev, &info->guid, info->eid, info->type);

		list_del(&info->list);
		kfree(info);
	}
}

static int logic_ummu_invalidate_cfg(struct ummu_base_domain *domain)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	const struct ummu_device_helper *helper = get_agent_helper();
	struct logic_ummu_domain *logic_domain;
	struct ummu_base_domain *base_domain;
	int ret;

	if (!core_ops || !core_ops->invalidate_cfg) {
		pr_err("invalid core_ops.\n");
		return -EOPNOTSUPP;
	}

	logic_domain = base_to_logic_domain(domain);
	if (!logic_domain->agent_domain) {
		pr_err("invalid agent_domain.\n");
		return -ENXIO;
	}

	ret = core_ops->invalidate_cfg(logic_domain->agent_domain);
	if (ret) {
		pr_err("invalidate cfg table failed.\n");
		return ret;
	}

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list) {
		if (base_domain == logic_domain->agent_domain)
			continue;

		if (core_ops->cfg_sync)
			core_ops->cfg_sync(base_domain);

		if (helper && helper->sync_iotlb_all)
			helper->sync_iotlb_all(&base_domain->domain);
	}

	return 0;
}

int logic_ummu_register_support_attr(tdev_select_logic_ummu func)
{
	struct support_cb *scb_entry;

	guard(spinlock)(&support_cb_list_lock);
	list_for_each_entry(scb_entry, &support_cb_list_head, node) {
		if (scb_entry->func == func) {
			pr_err("target func exist\n");
			return -EEXIST;
		}
	}

	scb_entry = kzalloc(sizeof(*scb_entry), GFP_ATOMIC);
	if (!scb_entry)
		return -ENOMEM;

	scb_entry->func = func;
	list_add_tail(&scb_entry->node, &support_cb_list_head);

	return 0;
}
EXPORT_SYMBOL_NS_GPL(logic_ummu_register_support_attr, UMMU_INTERNAL);

void logic_ummu_unregister_support_attr(tdev_select_logic_ummu func)
{
	struct support_cb *scb_entry, *next;

	guard(spinlock)(&support_cb_list_lock);
	list_for_each_entry_safe(scb_entry, next, &support_cb_list_head, node) {
		if (scb_entry->func == func) {
			list_del(&scb_entry->node);
			kfree(scb_entry);
		}
	}
}
EXPORT_SYMBOL_NS_GPL(logic_ummu_unregister_support_attr, UMMU_INTERNAL);

static bool logic_ummu_device_support_attr(struct ummu_core_device *core_device,
					   struct tdev_attr *attr)
{
	struct hisi_ummu_tdev_info *info;
	struct support_cb *scb_entry;
	bool select_logic_ummu;

	if (!attr->priv || !attr->priv_len)
		return true;

	if (attr->priv_len < sizeof(struct hisi_ummu_tdev_info)) {
		pr_err("para is invalid.\n");
		return false;
	}

	guard(spinlock)(&support_cb_list_lock);
	list_for_each_entry(scb_entry, &support_cb_list_head, node) {
		if (scb_entry->func(attr, &select_logic_ummu))
			return select_logic_ummu;
	}

	info = (struct hisi_ummu_tdev_info *)attr->priv;
	return !info->v1.on_chip;
}

static int logic_ummu_get_hw_cap(struct device *dev, u32 *hw_cap)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();

	if (!core_ops || !core_ops->get_hw_cap)
		return -EOPNOTSUPP;

	return core_ops->get_hw_cap(dev, hw_cap);
}

static int logic_ummu_dev_config(struct device *dev, int type, int command, void *data)
{
	const struct ummu_core_ops *core_ops = get_agent_core_ops();
	struct ummu_base_domain *ummu_base_domain;
	struct logic_ummu_domain *logic_domain;
	struct iommu_domain *domain;
	int ret;

	if (!core_ops || !core_ops->dev_config || !core_ops->cfg_sync_all)
		return -EOPNOTSUPP;

	domain = iommu_get_domain_for_dev(dev);
	if (!domain) {
		dev_err(dev, "invalid device.\n");
		return -ENODEV;
	}
	logic_domain = iommu_to_logic_domain(domain);
	if (!logic_domain->agent_domain) {
		pr_err("invalid agent_domain.\n");
		return -EINVAL;
	}

	ret = core_ops->dev_config(dev, type, command, data);
	if (ret)
		return ret;

	list_for_each_entry(ummu_base_domain, &logic_domain->base_domain.list, list) {
		if (ummu_base_domain == logic_domain->agent_domain)
			continue;

		core_ops->cfg_sync_all(ummu_base_domain);
	}

	return 0;
}

static void logic_ummu_tlb_inv_walk(struct iommu_domain *domain, unsigned long iova,
				    size_t size, size_t pgsize)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(domain);
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_base_domain *base_domain, *next;
	struct iommu_iotlb_gather gather = {
		.start = iova,
		.end = iova + size - 1,
		.pgsize = pgsize,
	};

	if (helper && helper->sync_tlb)
		list_for_each_entry_safe(base_domain, next, &logic_domain->base_domain.list, list)
			helper->sync_tlb(&base_domain->domain, &gather);
}

static struct ummu_core_ops logic_ummu_core_ops = {
	.cfg_sync_all = logic_ummu_cfg_sync_all,
	.cfg_sync = logic_ummu_cfg_sync,
	.get_resource = logic_ummu_get_resource,
	.put_resource = logic_ummu_put_resource,
	.add_eid = logic_ummu_add_eid,
	.del_eid = logic_ummu_del_eid,
	.invalidate_cfg = logic_ummu_invalidate_cfg,
	.tdev_support_attr = logic_ummu_device_support_attr,
	.get_hw_cap = logic_ummu_get_hw_cap,
	.dev_config = logic_ummu_dev_config,
	.tlb_inv_walk = logic_ummu_tlb_inv_walk,
};

/* workaround. should be in macro */
static void gen_iommu_ops(const struct iommu_ops *src, struct iommu_ops *dst)
{
	__GEN_OPS(capable, src, dst);
	__GEN_OPS(hw_info, src, dst);
	__GEN_OPS(domain_alloc, src, dst);
	__GEN_OPS(domain_alloc_user_v2, src, dst);
	__GEN_OPS(domain_alloc_paging, src, dst);
	__GEN_OPS(domain_alloc_sva, src, dst);
	__GEN_OPS(probe_device, src, dst);
	__GEN_OPS(release_device, src, dst);
	__GEN_OPS(probe_finalize, src, dst);
	__GEN_OPS(device_group, src, dst);
	__GEN_OPS(get_resv_regions, src, dst);
	__GEN_OPS(of_xlate, src, dst);
	__GEN_OPS(is_attach_deferred, src, dst);
	__GEN_OPS(dev_enable_feat, src, dst);
	__GEN_OPS(dev_disable_feat, src, dst);
	__GEN_OPS(page_response, src, dst);
	__GEN_OPS(def_domain_type, src, dst);
#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
	__GEN_OPS(remove_dev_pasid, src, dst);
#endif
	__GEN_OPS(set_group_qos_params, src, dst);
	__GEN_OPS(get_group_qos_params, src, dst);
	__GEN_OPS(viommu_alloc, src, dst);
}

static void gen_iommu_domain_ops(const struct iommu_domain_ops *src, struct iommu_domain_ops *dst)
{
	__GEN_OPS(attach_dev, src, dst);
#if IS_ENABLED(CONFIG_UB_UMMU_SVA)
	__GEN_OPS(set_dev_pasid, src, dst);
#endif
	__GEN_OPS(map_pages, src, dst);
	__GEN_OPS(unmap_pages, src, dst);
	__GEN_OPS(flush_iotlb_all, src, dst);
	__GEN_OPS(iotlb_sync, src, dst);
	__GEN_OPS(iova_to_phys, src, dst);
	__GEN_OPS(enforce_cache_coherency, src, dst);
	__GEN_OPS(free, src, dst);
	__GEN_OPS(get_msi_mapping_domain, src, dst);
}

static int init_ummu_device(struct ummu_device *ummu,
			    const struct iommu_ops *iommu_ops,
			    const struct ummu_core_ops *core_ops)
{
	struct ummu_core_init_args args = { 0 };

	args.iommu_ops = iommu_ops;
	args.core_ops = core_ops;
	args.hwdev = ummu->dev;
	args.tid_args.tid_ops = NULL;

	return ummu_core_device_init(&ummu->core_dev, &args);
}

static int logic_ummu_core_device_init(void)
{
	struct ummu_core_init_args args = { 0 };
	struct ummu_device *entry;
	int ret;

	args.iommu_ops = &logic_iommu_ops;
	args.core_ops = &logic_ummu_core_ops;
	args.hwdev = &logic_ummu_dev->dev;
	args.tid_args.tid_ops = ummu_core_tid_ops[PASID_OPS];
	args.tid_args.max_tid = logic_ummu.core_dev.iommu.max_pasids;
	args.tid_args.min_tid = logic_ummu.core_dev.iommu.min_pasids;
	ret = ummu_core_device_init(&logic_ummu.core_dev, &args);
	if (ret) {
		pr_err("init ummu core device failed.\n");
		return ret;
	}
	/* sync tid manager to all device */
	list_for_each_entry(entry, &logic_ummu.dev_list, list)
		entry->core_dev.tid_manager = logic_ummu.core_dev.tid_manager;

	return 0;
}

static void logic_ummu_core_device_deinit(void)
{
	struct ummu_device *entry;

	list_for_each_entry(entry, &logic_ummu.dev_list, list)
		entry->core_dev.tid_manager = NULL;

	ummu_core_device_deinit(&logic_ummu.core_dev);
}

static int logic_ummu_device_add_agent(struct ummu_device *ummu)
{
	struct iommu_domain_ops *domain_ops;
	const struct iommu_ops *drv_ops;

	domain_ops = kzalloc(sizeof(*domain_ops), GFP_KERNEL);
	if (!domain_ops)
		return -ENOMEM;

	drv_ops = ummu->core_dev.iommu.ops;
	logic_ummu.agent_device = ummu;
	logic_ummu.core_dev.iommu.min_pasids = ummu->core_dev.iommu.min_pasids;
	logic_ummu.core_dev.iommu.max_pasids = ummu->core_dev.iommu.max_pasids;
	logic_iommu_ops.pgsize_bitmap = ummu->core_dev.iommu.ops->pgsize_bitmap;
	gen_iommu_ops((struct iommu_ops *)drv_ops, (struct iommu_ops *)&logic_iommu_ops);
	gen_iommu_domain_ops(drv_ops->default_domain_ops, domain_ops);
	logic_iommu_ops.default_domain_ops = domain_ops;
	return 0;
}

static void logic_ummu_device_del_agent(void)
{
	logic_ummu.agent_device = NULL;
	logic_ummu.core_dev.iommu.min_pasids = UMMU_NO_TID;
	logic_ummu.core_dev.iommu.max_pasids = UMMU_NO_TID;
	kfree(logic_iommu_ops.default_domain_ops);
	logic_iommu_ops.default_domain_ops = NULL;
}

static int update_logic_ummu(struct ummu_device *ummu)
{
	int ret = 0;

	logic_ummu.ummu_cnt++;
	list_add_tail(&ummu->list, &logic_ummu.dev_list);
	if (!logic_ummu.agent_device) {
		ret = logic_ummu_device_add_agent(ummu);
		if (ret) {
			pr_err("add agent failed.\n");
			goto out_del_list;
		}
	}
	if (logic_ummu.ummu_cnt == global_ummu_cnt) {
		ret = logic_ummu_core_device_init();
		if (ret) {
			pr_err("logic ummu core device init failed, ret = %d.\n", ret);
			goto out_del_agent;
		}
		ret = ummu_core_device_register(&logic_ummu.core_dev, REGISTER_TYPE_GLOBAL);
		if (ret) {
			pr_err("register to ummu core failed, ret = %d.\n", ret);
			goto out_deinit_logic_ummu;
		}

		logic_iommu_ops.identity_domain = logic_ummu_domain_alloc_identity();
		if (IS_ERR(logic_iommu_ops.identity_domain)) {
			pr_err("init identity domain failed:%ld.\n",
				PTR_ERR(logic_iommu_ops.identity_domain));
			ret = -EOPNOTSUPP;
			goto out_unregister;
		}
	}
	return 0;

out_unregister:
	ummu_core_device_unregister(&logic_ummu.core_dev);
out_deinit_logic_ummu:
	logic_ummu_core_device_deinit();
out_del_agent:
	if (ummu == logic_ummu.agent_device)
		logic_ummu_device_del_agent();
out_del_list:
	list_del(&ummu->list);
	logic_ummu.ummu_cnt--;
	return ret;
}

void logic_ummu_plbi_free_bit(struct iommu_domain *d, u32 next_lvl_idx, u32 next_lvl_offset)
{
	struct logic_ummu_domain *logic_domain = iommu_to_logic_domain(d);
	const struct ummu_device_helper *helper = get_agent_helper();
	struct ummu_base_domain *base_domain;

	if (!helper || !helper->plbi_free_bit) {
		pr_err("find agent domain failed.\n");
		return;
	}

	list_for_each_entry(base_domain, &logic_domain->base_domain.list, list)
		helper->plbi_free_bit(&base_domain->domain, next_lvl_idx, next_lvl_offset);
}

int logic_add_ummu_device(struct ummu_device *ummu,
			  const struct iommu_ops *iommu_ops,
			  const struct ummu_core_ops *core_ops)
{
	int ret;

	guard(mutex)(&logic_ummu.dev_mutex);
	if (logic_ummu.ummu_cnt >= global_ummu_cnt) {
		pr_err("unexpected ummu was added.\n");
		return -EINVAL;
	}
	ret = init_ummu_device(ummu, iommu_ops, core_ops);
	if (ret) {
		pr_err("setup ummu device failed, ret = %d.\n", ret);
		return ret;
	}
	ret = update_logic_ummu(ummu);
	if (ret) {
		pr_err("update logic ummu failed.\n");
		ummu_core_device_deinit(&ummu->core_dev);
		return ret;
	}

	return 0;
}

void logic_remove_ummu_device(struct ummu_device *ummu)
{
	guard(mutex)(&logic_ummu.dev_mutex);
	if (!logic_ummu.ummu_cnt) {
		pr_err("unexpected number of UMMUs\n");
		return;
	}

	logic_identity_dev_free();
	logic_ummu_domain_identity_free();

	if (logic_ummu.ummu_cnt == global_ummu_cnt) {
		ummu_core_device_unregister(&logic_ummu.core_dev);
		remove_all_eid();
		logic_ummu_core_device_deinit();
	}

	if (ummu == logic_ummu.agent_device)
		logic_ummu_device_del_agent();

	ummu_core_device_deinit(&ummu->core_dev);
	list_del(&ummu->list);
	logic_ummu.ummu_cnt--;

	dev_info(ummu->dev, "logic ummu remove ummu instance successful!\n");
}

static inline struct fwnode_handle *logic_ummu_alloc_fwnode_static(void)
{
	struct fwnode_handle *handle;

	handle = kzalloc(sizeof(*handle), GFP_KERNEL);
	if (!handle)
		return NULL;

	fwnode_init(handle, &logic_ummu_static_fwnode_ops);

	return handle;
}

static const char *get_domain_type_str(u32 domain_type)
{
	switch (domain_type) {
	case IOMMU_DOMAIN_DMA:
		return "IOMMU_DOMAIN_DMA";
	case IOMMU_DOMAIN_IDENTITY:
		return "IOMMU_DOMAIN_IDENTITY";
	case IOMMU_DOMAIN_SVA:
		return "IOMMU_DOMAIN_SVA";
	default:
		return "UNKNOWN DOMAIN TYPE";
	}
}

static ssize_t tid_type_store(struct device *dev,
			      struct device_attribute *attr,
			      const char *buf, size_t count)
{
	struct ummu_core_device *ummu_core;
	u32 tid = 0, tid_type;
	int ret;

	ret = kstrtouint(buf, 0, &tid);
	if (ret < 0 || tid >= UMMU_INVALID_TID)
		return -EINVAL;

	ummu_core = to_ummu_core(dev_to_iommu_device(dev));
	ret = ummu_core_get_tid_type(ummu_core, tid, &tid_type);
	if (ret) {
		pr_err("Invalid tid = 0x%x, ret = %d.\n", tid, ret);
		return ret;
	}

	pr_info("tid = 0x%x, domain_type = %s.\n", tid, get_domain_type_str(tid_type));

	return (ssize_t)count;
}
static DEVICE_ATTR_WO(tid_type);

static struct attribute *logic_ummu_attrs[] = {
	&dev_attr_tid_type.attr,
	NULL,
};

static struct attribute_group logic_ummu_group = {
	.name = NULL,
	.attrs = logic_ummu_attrs,
};

const struct attribute_group *logic_ummu_groups[] = {
	&logic_ummu_group,
	NULL,
};

int logic_ummu_device_init(void)
{
	int ret;

	logic_ummu_dev = platform_device_alloc("logic-ummu", PLATFORM_DEVID_NONE);
	if (!logic_ummu_dev) {
		pr_err("alloc logic ummu device failed.\n");
		return -ENOMEM;
	}

	logic_ummu_fwnode = logic_ummu_alloc_fwnode_static();
	if (!logic_ummu_fwnode) {
		ret = -ENOMEM;
		pr_err("logic_ummu_alloc_fwnode_static failed.\n");
		goto out_pdev_put;
	}
	logic_ummu_dev->dev.fwnode = logic_ummu_fwnode;
	logic_ummu_dev->dev.fwnode->dev = &logic_ummu_dev->dev;
	device_set_pm_not_required(&logic_ummu_dev->dev);

	ret = platform_device_add(logic_ummu_dev);
	if (ret) {
		pr_err("add logic ummu device failed\n");
		goto out_free_fwnode;
	}
	ret = iommu_device_sysfs_add(&logic_ummu.core_dev.iommu, NULL, logic_ummu_groups,
				     "%s", "logic_ummu");
	if (ret) {
		pr_err("register logic ummu to sysfs failed.\n");
		goto out_pdev_del;
	}
	logic_ummu.ummu_cnt = 0;
	logic_ummu.core_dev.iommu.max_pasids = UMMU_NO_TID;
	INIT_LIST_HEAD(&logic_ummu.dev_list);
	mutex_init(&logic_ummu.dev_mutex);
	global_ummu_cnt = get_ummu_count();

	return 0;
out_pdev_del:
	platform_device_del(logic_ummu_dev);
out_free_fwnode:
	kfree(logic_ummu_fwnode);
	logic_ummu_fwnode = NULL;
out_pdev_put:
	platform_device_put(logic_ummu_dev);
	return ret;
}

void logic_ummu_device_exit(void)
{
	struct ummu_device *ummu, *next;
	unsigned long index;
	uintptr_t *ops;

	xa_for_each(&logic_ummu_ops_info, index, ops)
		kfree(ops);

	if (logic_ummu.ummu_cnt != 0 || !list_empty(&logic_ummu.dev_list)) {
		list_for_each_entry_safe(ummu, next, &logic_ummu.dev_list, list)
			logic_remove_ummu_device(ummu);

		pr_warn("unexpected ummu instances during exit.\n");
	}
	iommu_device_sysfs_remove(&logic_ummu.core_dev.iommu);
	platform_device_unregister(logic_ummu_dev);
	kfree(logic_ummu_fwnode);
	logic_ummu_fwnode = NULL;
}
