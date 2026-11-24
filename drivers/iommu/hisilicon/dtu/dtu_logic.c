// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu logic device aggregation layer.
 */

#define pr_fmt(fmt) "[ub dtu]: " fmt

#include <linux/err.h>
#include <linux/iommu.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/sizes.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>
#include <linux/hisi_ummu.h>

#include "dtu_internal.h"

static struct ub_dtu_logic_dev g_logic_dtu;

static u32 dts_node_count;

static u32 ub_dtu_count_nodes(void)
{
	struct device_node *np;
	u32 count = 0;

	for_each_compatible_node(np, NULL, "ub,dtu")
		count++;

	return count;
}

static struct iommu_domain *ub_dtu_domain_alloc(unsigned int type)
{
	struct ub_dtu_logic_domain *dtu_dom;

	switch (type) {
	case IOMMU_DOMAIN_DMA:
	case IOMMU_DOMAIN_DMA_FQ:
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	dtu_dom = kzalloc(sizeof(*dtu_dom), GFP_KERNEL);
	if (!dtu_dom)
		return ERR_PTR(-ENOMEM);

	INIT_LIST_HEAD(&dtu_dom->win_list);
	dtu_dom->base_domain.tid = UMMU_INVALID_TID;
	return &dtu_dom->base_domain.domain;
}

static struct iommu_device *ub_dtu_probe_device(struct device *dev)
{
	struct ub_dtu_master *master;

	if (!dev_iommu_fwspec_get(dev))
		return ERR_PTR(-ENODEV);

	master = kzalloc(sizeof(*master), GFP_KERNEL);
	if (!master)
		return ERR_PTR(-ENOMEM);

	master->logic_dtu = &g_logic_dtu;
	dev_iommu_priv_set(dev, master);
	return &g_logic_dtu.core_dev.iommu;
}

static void ub_dtu_release_device(struct device *dev)
{
	struct ub_dtu_master *master = dev_iommu_priv_get(dev);

	dev_iommu_priv_set(dev, NULL);
	kfree(master);
}

static struct iommu_group *ub_dtu_device_group(struct device *dev)
{
	return generic_device_group(dev);
}

static bool ub_dtu_tdev_support_attr(struct ummu_core_device *core_device,
				       struct tdev_attr *attr)
{
	struct hisi_ummu_tdev_info *info;

	if (!attr || !attr->priv || attr->priv_len < sizeof(*info))
		return false;

	info = (struct hisi_ummu_tdev_info *)attr->priv;
	if (info->version != 1)
		return false;

	return info->v2.on_chip;
}

static struct iommu_ops ub_dtu_iommu_ops = {
	.domain_alloc = ub_dtu_domain_alloc,
	.probe_device = ub_dtu_probe_device,
	.release_device = ub_dtu_release_device,
	.device_group = ub_dtu_device_group,
	.default_domain_ops = &ub_dtu_domain_ops,
	.pgsize_bitmap = SZ_4K,
	.owner = THIS_MODULE,
};

static struct ummu_core_ops ub_dtu_core_ops = {
	.tdev_support_attr = ub_dtu_tdev_support_attr,
};


static int ub_dtu_core_device_init(void)
{
	struct ub_dtu_device *first_dev;
	struct ummu_core_init_args args = { 0 };

	first_dev = list_first_entry(&g_logic_dtu.dev_list,
				     struct ub_dtu_device, list);

	args.iommu_ops = &ub_dtu_iommu_ops;
	args.core_ops  = &ub_dtu_core_ops;
	args.hwdev = first_dev->dev;
	args.tid_args.tid_ops = NULL;
	return ummu_core_device_init(&g_logic_dtu.core_dev, &args);
}

static int ub_dtu_logic_register(void)
{
	struct ub_dtu_device *first_dev;
	int ret;

	first_dev = list_first_entry(&g_logic_dtu.dev_list,
				     struct ub_dtu_device, list);

	ret = ub_dtu_core_device_init();
	if (ret) {
		pr_err("logic dtu core device init failed, ret=%d.\n", ret);
		return ret;
	}

	ret = iommu_device_sysfs_add(&g_logic_dtu.core_dev.iommu,
				     first_dev->dev, NULL,
				     "ub-dtu.%s",
				     dev_name(first_dev->dev));
	if (ret) {
		pr_err("iommu sysfs add failed, ret=%d.\n", ret);
		goto err_deinit;
	}

	ret = ummu_core_device_register(&g_logic_dtu.core_dev,
					REGISTER_TYPE_NORMAL);
	if (ret) {
		pr_err("register to ummu core failed, ret=%d.\n", ret);
		goto err_sysfs;
	}

	return 0;

err_sysfs:
	iommu_device_sysfs_remove(&g_logic_dtu.core_dev.iommu);
err_deinit:
	ummu_core_device_deinit(&g_logic_dtu.core_dev);
	return ret;
}

static void ub_dtu_logic_unregister(void)
{
	ummu_core_device_unregister(&g_logic_dtu.core_dev);
	iommu_device_sysfs_remove(&g_logic_dtu.core_dev.iommu);
	ummu_core_device_deinit(&g_logic_dtu.core_dev);
}

int ub_dtu_logic_add_device(struct ub_dtu_device *dtu)
{
	int ret = 0;

	guard(mutex)(&g_logic_dtu.dev_mutex);

	if (g_logic_dtu.dtu_cnt >= dts_node_count) {
		dtu_err(dtu, "unexpected dtu device was added.\n");
		return -EINVAL;
	}

	list_add_tail(&dtu->list, &g_logic_dtu.dev_list);
	g_logic_dtu.dtu_cnt++;

	if (g_logic_dtu.dtu_cnt == dts_node_count) {
		ret = ub_dtu_logic_register();
		if (ret) {
			pr_err("register logic dtu failed, ret=%d.\n", ret);
			list_del(&dtu->list);
			g_logic_dtu.dtu_cnt--;
		}
	}
	return ret;
}

void ub_dtu_logic_remove_device(struct ub_dtu_device *dtu)
{
	guard(mutex)(&g_logic_dtu.dev_mutex);

	if (!g_logic_dtu.dtu_cnt) {
		pr_err("unexpected number of DTU devices\n");
		return;
	}

	if (g_logic_dtu.dtu_cnt == dts_node_count)
		ub_dtu_logic_unregister();

	list_del(&dtu->list);
	g_logic_dtu.dtu_cnt--;
}

void ub_dtu_logic_init(void)
{
	INIT_LIST_HEAD(&g_logic_dtu.dev_list);
	mutex_init(&g_logic_dtu.dev_mutex);
	g_logic_dtu.dtu_cnt = 0;
	dtu_win_mgr_init(&g_logic_dtu.mgr);

	dts_node_count = ub_dtu_count_nodes();
	pr_info("logic dtu init, dts node count = %u.\n", dts_node_count);
}
