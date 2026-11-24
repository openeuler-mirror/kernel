// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: ub-dtu device probe and remove.
 */

#define pr_fmt(fmt) "[ub dtu]: " fmt

#include <linux/err.h>
#include <linux/io.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/slab.h>
#include <linux/ummu_core.h>
#include <ub/ubfi/ubfi.h>

#include "../ummu.h"
#include "dtu_internal.h"

#define DTU_REG_CMDQ_BASE_IDX	1
#define DTU_OPTION_USE_IMP	BIT(0)

static bool g_logic_inited;

static int ub_dtu_get_die_index(struct device *dev, u32 *die_index)
{
	struct fwnode_handle *fwnode = dev_fwnode(dev);
	struct ubrt_fwnode *fw;

	if (!fwnode)
		return -EINVAL;

	fw = ubrt_fwnode_get(fwnode);
	if (!fw || fw->type != UBRT_UMMU)
		return -ENXIO;

	*die_index = fw->index;
	return 0;
}

static int ub_dtu_find_node(u32 die_index, struct platform_device **pdev,
			    u32 *option)
{
	struct device_node *np;
	u32 node_idx;

	for_each_compatible_node(np, NULL, "ub,dtu") {
		if (of_property_read_u32(np, "index", &node_idx)) {
			of_node_put(np);
			return -EIO;
		}
		if (node_idx == die_index)
			goto found;
	}
	return -ENODEV;

found:
	*pdev = of_find_device_by_node(np);
	of_node_put(np);
	if (!(*pdev))
		return -EIO;

	if (of_property_read_u32((*pdev)->dev.of_node, "option", option)) {
		put_device(&(*pdev)->dev);
		return -EIO;
	}
	return 0;
}

static int ub_dtu_device_init(struct ub_dtu_device *dtu)
{
	struct device_node *np = dtu->pdev->dev.of_node;
	struct resource res;
	int ret;

	ret = of_address_to_resource(np, DTU_REG_CMDQ_BASE_IDX, &res);
	if (ret) {
		dtu_err(dtu, "parse cmdq_base reg failed (ret=%d).\n", ret);
		return ret;
	}

	if (!request_mem_region(res.start, resource_size(&res),
				dev_name(dtu->dev))) {
		dtu_err(dtu, "request cmdq_base mem region failed.\n");
		return -EBUSY;
	}

	dtu->cmdq_base = ioremap(res.start, resource_size(&res));
	if (!dtu->cmdq_base) {
		release_mem_region(res.start, resource_size(&res));
		dtu_err(dtu, "ioremap cmdq_base failed.\n");
		return -ENOMEM;
	}
	dtu->cmdq_res = res;

	ret = ub_dtu_cmdq_init(dtu);
	if (ret) {
		iounmap(dtu->cmdq_base);
		dtu->cmdq_base = NULL;
		release_mem_region(dtu->cmdq_res.start,
				   resource_size(&dtu->cmdq_res));
		dtu->cmdq_res = (struct resource){ 0 };
		dtu_err(dtu, "cmdq init failed, ret=%d.\n", ret);
	}
	return ret;
}

static void ub_dtu_device_uninit(struct ub_dtu_device *dtu)
{
	ub_dtu_cmdq_uninit(dtu);

	if (dtu->cmdq_base)
		iounmap(dtu->cmdq_base);
	if (dtu->cmdq_res.start)
		release_mem_region(dtu->cmdq_res.start,
				   resource_size(&dtu->cmdq_res));
	dtu->cmdq_base = NULL;
}


int ub_dtu_probe(struct device *dev)
{
	struct platform_device *pdev;
	struct ub_dtu_device *dtu;
	u32 die_index, option;
	int ret;

	ret = ub_dtu_get_die_index(dev, &die_index);
	if (ret)
		return ret;

	ret = ub_dtu_find_node(die_index, &pdev, &option);
	if (ret == -ENODEV) {
		pr_debug("DTU no DTS node on die %u\n", die_index);
		return 0;
	}
	if (ret)
		return ret;

	if (!g_logic_inited) {
		ub_dtu_logic_init();
		g_logic_inited = true;
	}

	dtu = devm_kzalloc(&pdev->dev, sizeof(*dtu), GFP_KERNEL);
	if (!dtu) {
		ret = -ENOMEM;
		goto err_put;
	}

	dtu->pdev = pdev;
	dtu->dev = &pdev->dev;
	dtu->index = die_index;
	dtu->use_imp_cmdq = !!(option & DTU_OPTION_USE_IMP);
	if (!dtu->use_imp_cmdq) {
		dev_err(&pdev->dev,
			"ub-dtu: non-IMP mode unsupported (option=0x%x)\n",
			option);
		ret = -ENODEV;
		goto err_put;
	}
	platform_set_drvdata(pdev, dtu);

	ret = ub_dtu_device_init(dtu);
	if (ret) {
		dev_err(&pdev->dev, "ub-dtu device init failed, ret=%d\n", ret);
		goto err_clr_drvdata;
	}

	ret = ub_dtu_logic_add_device(dtu);
	if (ret) {
		dev_err(&pdev->dev, "ub-dtu logic add failed, ret=%d\n", ret);
		ub_dtu_device_uninit(dtu);
		goto err_clr_drvdata;
	}

	put_device(&pdev->dev);
	dev_info(&pdev->dev, "ub-dtu probe die=%u\n", die_index);
	return 0;

err_clr_drvdata:
	platform_set_drvdata(pdev, NULL);
err_put:
	put_device(&pdev->dev);
	return ret;
}

void ub_dtu_remove(struct device *dev)
{
	struct platform_device *pdev;
	struct ub_dtu_device *dtu;
	u32 die_index, option;

	if (ub_dtu_get_die_index(dev, &die_index))
		return;

	if (ub_dtu_find_node(die_index, &pdev, &option))
		return;

	dtu = dev_get_drvdata(&pdev->dev);
	if (dtu) {
		dev_info(&pdev->dev, "ub-dtu remove die=%u\n", die_index);
		ub_dtu_logic_remove_device(dtu);
		ub_dtu_device_uninit(dtu);
		platform_set_drvdata(pdev, NULL);
	}
	put_device(&pdev->dev);
}
