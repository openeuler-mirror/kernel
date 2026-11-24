// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu domain operations (map / unmap / attach).
 */

#define pr_fmt(fmt) "[ub dtu]: " fmt

#include <linux/bitmap.h>
#include <linux/err.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/property.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/types.h>

#include "dtu_internal.h"

#define DTU_MAX_TID 4095
#define DTU_MIN_TID 1
static DEFINE_MUTEX(ub_dtu_config_lock);

static DECLARE_BITMAP(ub_dtu_tid_bitmap, DTU_MAX_TID + 1);

static struct ub_dtu_win *ub_dtu_find_win_by_iova(struct ub_dtu_logic_domain *dtu_dom,
						  unsigned long iova)
{
	struct ub_dtu_win *win;

	list_for_each_entry(win, &dtu_dom->win_list, node)
		if (win->iova == iova)
			return win;

	return NULL;
}

static void ub_dtu_win_release(struct ub_dtu_logic_domain *dtu_dom,
				 struct ub_dtu_win *win)
{
	struct ub_dtu_logic_dev *logic_dtu = dtu_dom->logic_dtu;
	struct dtu_addr_window empty = {};

	if (logic_dtu) {
		ub_dtu_config_all_dev(dtu_dom, &empty, win->win_id, 0, false, NULL);
		dtu_win_remove_by_id(&logic_dtu->mgr, win->win_id);
	}

	list_del(&win->node);
	kfree(win);
}

static void ub_dtu_win_list_free(struct ub_dtu_logic_domain *dtu_dom)
{
	struct ub_dtu_win *win, *tmp;

	list_for_each_entry_safe(win, tmp, &dtu_dom->win_list, node)
		ub_dtu_win_release(dtu_dom, win);
}


static void ub_dtu_fill_config_cmd(struct ub_dtu_logic_domain *dtu_dom,
				     struct dtu_cfg_tbl *req, int prot,
				     const struct dtu_addr_window *win,
				     u8 win_num, bool enable)
{
	u64 iova_base = win->base_iova;
	u64 pa_base = win->base_paddr;
	u64 limit_addr;

	limit_addr = iova_base + win->size - SZ_1M;

	memset(req, 0, sizeof(*req));

	req->en = enable ? 1 : 0;
	req->exclusive = 0;

	req->perm_read = !!(prot & IOMMU_READ);
	req->perm_write = !!(prot & IOMMU_WRITE);

	req->perm_atomic = 1;
	req->bufferable = 1;
	req->modified = 1;
	req->read_allocate = 1;
	req->write_allocate = 1;
	req->snoop = 1;

	req->win_num = cpu_to_le16(win_num);
	req->tid = cpu_to_le32(dtu_dom->base_domain.tid);
	req->base_addr_l = cpu_to_le32(lower_32_bits(iova_base));
	req->base_addr_h = cpu_to_le32(upper_32_bits(iova_base));
	req->limit_addr_l = cpu_to_le32(lower_32_bits(limit_addr));
	req->limit_addr_h = cpu_to_le32(upper_32_bits(limit_addr));
	req->target_addr_l = cpu_to_le32(lower_32_bits(pa_base));
	req->target_addr_h = cpu_to_le32(upper_32_bits(pa_base));
}

static int ub_dtu_config_one(struct ub_dtu_device *dtu,
			       struct ub_dtu_logic_domain *dtu_dom,
			       const struct dtu_addr_window *win, u8 win_num,
			       int prot, bool enable,
			       struct dtu_cmdq_desc *out_desc)
{
	struct dtu_cfg_tbl req;
	struct dtu_cmd_buf in;

	ub_dtu_fill_config_cmd(dtu_dom, &req, prot, win, win_num, enable);
	ub_dtu_fill_cmd_buf(&in, DTU_OPC_CONFIG_CMD, false, sizeof(req), &req);
	return ub_dtu_cmd_send_inout(dtu, &in, out_desc);
}

static int config_dev_enable(struct ub_dtu_device *phys_dev,
			     struct ub_dtu_logic_domain *dtu_dom,
			     const struct dtu_addr_window *win, u8 win_num,
			     int prot, u8 *imp_win_num)
{
	struct dtu_cmdq_desc resp;
	struct dtu_cfg_tbl *resp_tbl;
	int ret;

	ret = ub_dtu_config_one(phys_dev, dtu_dom, win, win_num, prot,
				  true, &resp);
	if (ret)
		return ret;

	resp_tbl = (struct dtu_cfg_tbl *)resp.data;
	*imp_win_num = (u8)le16_to_cpu(resp_tbl->win_num);
	return 0;
}

static int config_all_dev_enable(struct ub_dtu_logic_dev *logic_dtu,
				 struct ub_dtu_logic_domain *dtu_dom,
				 const struct dtu_addr_window *win, int prot,
				 u8 *out_imp_win_num)
{
	struct ub_dtu_device *phys_dev, *rb_dev;
	u8 imp_win_num;
	u8 this_win;
	int rb_ret;
	int ret;

	phys_dev = list_first_entry(&logic_dtu->dev_list,
				    struct ub_dtu_device, list);
	ret = config_dev_enable(phys_dev, dtu_dom, win, 0, prot, &imp_win_num);
	if (ret) {
		dtu_err(phys_dev, "enable failed on first dev, ret=%d.\n", ret);
		return ret;
	}

	list_for_each_entry_continue(phys_dev, &logic_dtu->dev_list, list) {
		ret = config_dev_enable(phys_dev, dtu_dom, win, imp_win_num,
					prot, &this_win);
		if (ret) {
			dtu_err(phys_dev,
				"enable failed, imp_win_num=%u, ret=%d. rolling back.\n",
				imp_win_num, ret);
			goto rollback;
		}

		if (WARN_ON(this_win != imp_win_num)) {
			dtu_err(phys_dev,
				"win_num mismatch: first=%u, this=%u.\n",
				imp_win_num, this_win);
			rb_ret = ub_dtu_config_one(phys_dev, dtu_dom, win,
						   this_win, 0, false, NULL);
			if (rb_ret)
				dtu_err(phys_dev,
					"rollback disable failed, win=%u, ret=%d.\n",
					this_win, rb_ret);
			ret = -EIO;
			goto rollback;
		}
	}

	if (out_imp_win_num)
		*out_imp_win_num = imp_win_num;
	return 0;

rollback:
	list_for_each_entry(rb_dev, &logic_dtu->dev_list, list) {
		if (rb_dev == phys_dev)
			break;

		rb_ret = ub_dtu_config_one(rb_dev, dtu_dom, win, imp_win_num,
					     0, false, NULL);
		if (rb_ret)
			dtu_err(rb_dev,
				"rollback disable failed, win=%u, ret=%d.\n",
				imp_win_num, rb_ret);
	}
	return ret;
}

static int config_all_dev_disable(struct ub_dtu_logic_dev *logic_dtu,
				  struct ub_dtu_logic_domain *dtu_dom,
				  const struct dtu_addr_window *win,
				  u8 win_id)
{
	struct ub_dtu_device *phys_dev;
	int ret;

	list_for_each_entry(phys_dev, &logic_dtu->dev_list, list) {
		ret = ub_dtu_config_one(phys_dev, dtu_dom, win, win_id, 0,
					  false, NULL);
		if (ret) {
			dtu_err(phys_dev,
				"disable failed, win_id=%u, ret=%d.\n",
				win_id, ret);
			return ret;
		}
	}
	return 0;
}

int ub_dtu_config_all_dev(struct ub_dtu_logic_domain *dtu_dom,
			    const struct dtu_addr_window *win, u8 win_num,
			    int prot, bool enable, u8 *out_imp_win_num)
{
	struct ub_dtu_logic_dev *logic_dtu = dtu_dom->logic_dtu;

	if (list_empty(&logic_dtu->dev_list))
		return -ENODEV;

	if (enable)
		return config_all_dev_enable(logic_dtu, dtu_dom, win, prot,
					     out_imp_win_num);

	return config_all_dev_disable(logic_dtu, dtu_dom, win, win_num);
}


/*
 * Free a domain and all its mapped windows.
 *
 * config_lock is a file-static global rather than a member of the
 * freed object, so holding it across kfree via guard is safe.
 */
static void ub_dtu_domain_free(struct iommu_domain *domain)
{
	struct ub_dtu_logic_domain *dtu_dom = to_ub_dtu_domain(domain);
	u32 tid = dtu_dom->base_domain.tid;

	guard(mutex)(&ub_dtu_config_lock);
	ub_dtu_win_list_free(dtu_dom);
	if (tid >= DTU_MIN_TID && tid <= DTU_MAX_TID)
		clear_bit(tid, ub_dtu_tid_bitmap);
	dtu_dom->logic_dtu = NULL;
	kfree(dtu_dom);
}

static int ub_dtu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	struct ub_dtu_logic_domain *dtu_dom = to_ub_dtu_domain(domain);
	struct ub_dtu_master *master;
	u32 tid;
	int ret;

	master = dev_iommu_priv_get(dev);
	if (!master || !master->logic_dtu) {
		pr_err("attach failed, no dtu master.\n");
		return -ENODEV;
	}

	if (dtu_dom->logic_dtu) {
		pr_err("attach failed, domain already occupied.\n");
		return -EEXIST;
	}

	ret = device_property_read_u32(dev, "assign-pasid", &tid);
	if (ret) {
		pr_err("attach failed, no assign-pasid.\n");
		return -EINVAL;
	}

	if (tid < DTU_MIN_TID || tid > DTU_MAX_TID) {
		pr_err("assign-pasid invalid.\n");
		return -EINVAL;
	}

	if (test_and_set_bit(tid, ub_dtu_tid_bitmap)) {
		pr_err("attach failed, tid %u already in use.\n", tid);
		return -EBUSY;
	}

	dtu_dom->base_domain.tid = tid;
	dtu_dom->logic_dtu = master->logic_dtu;

	return 0;
}

static int ub_dtu_map_pages(struct iommu_domain *domain, unsigned long iova,
			      phys_addr_t paddr, size_t pgsize, size_t pgcount,
			      int prot, gfp_t gfp, size_t *mapped)
{
	struct ub_dtu_logic_domain *dtu_dom = to_ub_dtu_domain(domain);
	struct ub_dtu_logic_dev *logic_dtu = dtu_dom->logic_dtu;
	struct dtu_addr_window win = {};
	struct ub_dtu_win *win_node;
	u8 imp_win_num;
	int ret;

	if (!logic_dtu)
		return -ENODEV;

	if (!((u32)prot & (IOMMU_READ | IOMMU_WRITE)))
		return -EACCES;

	win.size = pgsize * pgcount;

	if (!IS_ALIGNED(iova | paddr | win.size, SZ_1M) || win.size == 0)
		return -EINVAL;

	win.base_iova = iova;
	win.base_paddr = paddr;

	guard(mutex)(&ub_dtu_config_lock);

	ret = dtu_win_check(&logic_dtu->mgr, &win, &dtu_dom->win_list);
	if (ret)
		return ret;

	win_node = kzalloc(sizeof(*win_node), gfp);
	if (!win_node)
		return -ENOMEM;

	ret = ub_dtu_config_all_dev(dtu_dom, &win, 0, prot, true, &imp_win_num);
	if (ret) {
		kfree(win_node);
		return ret;
	}

	ret = dtu_win_save(&logic_dtu->mgr, imp_win_num, &win);
	if (ret) {
		pr_err("win_save failed, imp_win_num=%u, ret=%d. rolling back hw.\n",
		       imp_win_num, ret);
		ub_dtu_config_all_dev(dtu_dom, &win, imp_win_num, 0, false, NULL);
		kfree(win_node);
		return ret;
	}

	win_node->iova = iova;
	win_node->pa = paddr;
	win_node->size = win.size;
	win_node->win_id = imp_win_num;
	list_add_tail(&win_node->node, &dtu_dom->win_list);

	if (mapped)
		*mapped = win.size;
	return 0;
}

static size_t ub_dtu_unmap_pages(struct iommu_domain *domain,
				   unsigned long iova, size_t pgsize,
				   size_t pgcount,
				   struct iommu_iotlb_gather *gather __maybe_unused)
{
	struct ub_dtu_logic_domain *dtu_dom = to_ub_dtu_domain(domain);
	struct ub_dtu_win *win;
	size_t unmapped = 0;

	guard(mutex)(&ub_dtu_config_lock);

	win = ub_dtu_find_win_by_iova(dtu_dom, iova);
	if (!win)
		return 0;

	unmapped = win->size;
	ub_dtu_win_release(dtu_dom, win);

	return unmapped;
}

const struct iommu_domain_ops ub_dtu_domain_ops = {
	.attach_dev = ub_dtu_attach_dev,
	.map_pages = ub_dtu_map_pages,
	.unmap_pages = ub_dtu_unmap_pages,
	.free = ub_dtu_domain_free,
};
