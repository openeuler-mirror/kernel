// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 */

#define pr_fmt(fmt) "hisi_l3t: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/smp.h>
#include <linux/xarray.h>
#include <linux/irqchip.h>

#include "hisi_l3t.h"

#define LOCK_EN		BIT(0)
#define LOCK_DONE	BIT(1)
#define UNLOCK_EN	BIT(2)
#define UNLOCK_DONE	BIT(3)

DEFINE_MUTEX(l3t_mutex);
static DEFINE_XARRAY(l3t_mapping);

static int sccl_to_node_id(int id)
{
	int sccl_id, cpu;
	u64 mpidr;

	for_each_possible_cpu(cpu) {
		mpidr = cpu_logical_map(cpu);
		sccl_id = MPIDR_AFFINITY_LEVEL(mpidr, 3);
		if (sccl_id == id)
			return cpu_to_node(cpu);
	}

	pr_err("invalid sccl id: %d\n", id);
	return -EINVAL;
}

static int hisi_l3t_init_data(struct platform_device *pdev,
			      struct hisi_l3t *l3t)
{
	if (device_property_read_u32(&pdev->dev, "hisilicon,scl-id",
				     &l3t->sccl_id))
		return -EINVAL;

	if (device_property_read_u32(&pdev->dev, "hisilicon,ccl-id",
				     &l3t->ccl_id))
		return -EINVAL;

	l3t->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(l3t->base))
		return PTR_ERR(l3t->base);

	l3t->nid = sccl_to_node_id(l3t->sccl_id);
	if (l3t->nid < 0)
		return -EINVAL;

	return 0;
}

static int hisi_l3t_insert_to_sccl(struct hisi_sccl *sccl, struct hisi_l3t *l3t)
{
	void *tmp_l3t;

	if (sccl->ccl_cnt > l3t->ccl_id)
		goto set;

	tmp_l3t = krealloc(sccl->l3t,
			   (l3t->ccl_id + 1) * sizeof(struct hisi_l3t *),
			   GFP_KERNEL);
	if (!tmp_l3t)
		return -ENOMEM;

	sccl->ccl_cnt = l3t->ccl_id + 1;
	sccl->l3t = tmp_l3t;

set:
	sccl->l3t[l3t->ccl_id] = l3t;
	return 0;
}

/*
 * Use xarray to store the mapping b/t nid to sccl
 * all ccls belong be one sccl is store with vla in sccl->l3t
 */
static int hisi_l3t_init_mapping(struct device *dev, struct hisi_l3t *l3t)
{
	struct hisi_sccl *sccl;
	int ret = -ENOMEM;

	mutex_lock(&l3t_mutex);
	sccl = xa_load(&l3t_mapping, l3t->nid);
	if (!sccl) {
		sccl = devm_kzalloc(dev, sizeof(*sccl), GFP_KERNEL);
		if (!sccl)
			goto unlock;
		sccl->nid = l3t->nid;

		xa_store(&l3t_mapping, l3t->nid, sccl, GFP_KERNEL);
	}

	ret = hisi_l3t_insert_to_sccl(sccl, l3t);
unlock:
	mutex_unlock(&l3t_mutex);

	return ret;
}

/* write bit b_update and wait bit b_wait to be zero */
static void __l3t_update_and_wait(void __iomem *addr, u32 b_update, u32 b_wait)
{
	u32 val;

	writel(b_update, addr);

	do {
		val = readl(addr);
	} while ((val & b_wait) == 0);
}

static void __l3t_maintain(void __iomem *addr, int slot_idx,
			   unsigned long s_addr, int size, bool lock)
{
	if (slot_idx < 0 || slot_idx >= L3T_REG_NUM) {
		pr_err("slot index is invalid: %d\n", slot_idx);
		return;
	}

	if (!addr) {
		pr_err("invalid unlock addr\n");
		return;
	}

	addr += slot_idx * L3T_LOCK_STEP;

	writeq(s_addr, addr + L3T_LOCK_START_L);
	writel(size, addr + L3T_LOCK_AREA);

	if (lock)
		__l3t_update_and_wait(addr + L3T_LOCK_CTRL, LOCK_EN, LOCK_DONE);
	else
		__l3t_update_and_wait(addr + L3T_LOCK_CTRL, UNLOCK_EN,
				      UNLOCK_DONE);
}

void hisi_l3t_lock(struct hisi_l3t *l3t, int slot_idx, unsigned long s_addr,
		   int size)
{
	__l3t_maintain(l3t->base, slot_idx, s_addr, size, true);

	pr_debug("lock success. addr: %#lx, slot: %d, s_addr: %#lx, size: %#x\n",
		(unsigned long)l3t->base, slot_idx, s_addr, size);
}

void hisi_l3t_unlock(struct hisi_l3t *l3t, int slot_idx)
{
	__l3t_maintain(l3t->base, slot_idx, 0, 0, false);

	pr_debug("unlock success. addr: %#lx, slot: %d\n",
		 (unsigned long)l3t->base, slot_idx);
}

static void hisi_l3t_read_inner(void __iomem *addr, int locksel,
				unsigned long *s_addr, int *size)
{
	if (!addr) {
		*s_addr = 0;
		*size = 0;
		pr_err("invalid unlock addr\n");
		return;
	}

	*s_addr = readq(addr + L3T_LOCK_START_L + locksel * L3T_LOCK_STEP);
	*size = readl(addr + L3T_LOCK_AREA + locksel * L3T_LOCK_STEP);
}

void hisi_l3t_read(struct hisi_l3t *l3t, int slot_idx, unsigned long *s_addr,
		   int *size)
{
	if (slot_idx < 0 || slot_idx >= L3T_REG_NUM) {
		pr_err("slot index is invalid: %d\n", slot_idx);
		return;
	}

	return hisi_l3t_read_inner(l3t->base, slot_idx, s_addr, size);
}

struct hisi_sccl *hisi_l3t_get_sccl(int nid)
{
	return xa_load(&l3t_mapping, nid);
}

static const struct acpi_device_id hisi_l3t_acpi_match[] = {
	{ "HISI0501", },
	{}
};
MODULE_DEVICE_TABLE(acpi, hisi_l3t_acpi_match);

static int hisi_l3t_probe(struct platform_device *pdev)
{
	struct hisi_l3t *l3t;
	int ret;

	l3t = devm_kzalloc(&pdev->dev, sizeof(*l3t), GFP_KERNEL);
	if (!l3t)
		return -ENOMEM;

	platform_set_drvdata(pdev, l3t);

	ret = hisi_l3t_init_data(pdev, l3t);
	if (!ret) {
		l3t->dev = &pdev->dev;
		ret = hisi_l3t_init_mapping(&pdev->dev, l3t);
	}

	return ret;
}

static struct platform_driver hisi_l3t_driver = {
	.driver = {
		.name = "hisi_l3t",
		.acpi_match_table = ACPI_PTR(hisi_l3t_acpi_match),
		.suppress_bind_attrs = true,
	},
	.probe = hisi_l3t_probe,
};

static int __init hisi_l3t_init(void)
{
	mutex_init(&l3t_mutex);
	xa_init(&l3t_mapping);

	return platform_driver_register(&hisi_l3t_driver);
}
module_init(hisi_l3t_init);

static void hisi_l3t_destroy_sccl(void)
{
	struct hisi_sccl *sccl;
	unsigned long nid;

	xa_for_each(&l3t_mapping, nid, sccl)
		kfree(sccl->l3t);
}

static void __exit hisi_l3t_exit(void)
{
	hisi_l3t_destroy_sccl();
	xa_destroy(&l3t_mapping);

	platform_driver_unregister(&hisi_l3t_driver);
}
module_exit(hisi_l3t_exit);

MODULE_DESCRIPTION("HiSilicon SoC L3T driver");
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Ma Wupeng <mawupeng1@huawei.com>");
