// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 * Descriptor:
 * Parse and create ummu from UBRT(reported by ACPI) or UBIOS Info table (reported by DTS)
 */

#define pr_fmt(fmt)	"ubfi ummu: " fmt

#include <linux/platform_device.h>
#include <ub/ubfi/ubfi.h>
#include <linux/of_platform.h>

#include "ubrt.h"
#include "ub_fi.h"
#include "ubc.h"
#include "ummu.h"

struct ummu_sub_table {
	struct ub_table_header header;
	u16 count;
	u8 reserved[6];
	u8 node_data[] __counted_by(count);
};

#define UBRT_UMMU_PXM_VALID		0xFFFF
#define ACPI_UMMU_DEVICE_HID		"HISI0551"
#define ACPI_UMMU_PMU_DEVICE_HID	"HISI0571"
#define UMMU_INDEX_MASK			GENMASK(31, 0)
#define UMMU_TYPE_MASK			GENMASK_ULL(63, 32)

struct ummu_type_info {
	enum ubrt_node_type type;
	const char *name;
	const char *acpi_hid;
	const char *of_compat;
};

static const struct ummu_type_info ummu_types[] = {
	{
		.type      = UBRT_UMMU,
		.name      = "ummu",
		.acpi_hid  = ACPI_UMMU_DEVICE_HID,
		.of_compat = "ub,ummu",
	},
	{
		.type      = UBRT_UMMU_PMU,
		.name      = "ummu_pmu",
		.acpi_hid  = ACPI_UMMU_PMU_DEVICE_HID,
		.of_compat = "ub,ummu_pmu",
	},
};

static const struct ummu_type_info *ummu_get_type_info(enum ubrt_node_type type)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ummu_types); i++) {
		if (ummu_types[i].type == type)
			return &ummu_types[i];
	}
	return NULL;
}

static void ummu_get_node_addr(struct ummu_node *node, enum ubrt_node_type type,
			       u64 *base, u64 *size)
{
	if (type == UBRT_UMMU) {
		*base = node->base_addr;
		*size = node->addr_size;
	} else {
		*base = node->pmu_addr;
		*size = node->pmu_size;
	}
}

static int ummu_set_proximity(struct device *dev, struct ummu_node *node)
{
	int dev_node;

	if (node->pxm == UBRT_UMMU_PXM_VALID)
		return 0;

	if (firmware_mode == ACPI) {
		dev_node = pxm_to_node(node->pxm);
		if (dev_node != NUMA_NO_NODE && !node_online(dev_node))
			return -EINVAL;
	} else {
		dev_node = node->pxm;
		if (dev_node >= MAX_NUMNODES || !node_possible(dev_node))
			return -EINVAL;
	}

	set_dev_node(dev, dev_node);

	dev_info(dev, "UMMU mapped to Proximity domain : %u dev_node : %d\n",
		 node->pxm, dev_node);

	return 0;
}

static int ummu_add_resources(struct platform_device *pdev,
				     struct ummu_node *node,
				     enum ubrt_node_type type)
{
	struct resource *res __free(kfree);
	u64 base, size;

	ummu_get_node_addr(node, type, &base, &size);

	res = kcalloc(1, sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;

	res[0].start = base;
	res[0].end = base + size - 1;
	res[0].flags = IORESOURCE_MEM;

	return platform_device_add_resources(pdev, res, 1);
}

static int ummu_rename_device(struct platform_device *pdev,
			      const struct ummu_type_info *info)
{
	static int device_count[ARRAY_SIZE(ummu_types)];
	unsigned int idx = info - ummu_types;
	char new_name[32];
	int ret;

	ret = snprintf(new_name, sizeof(new_name), "%s.%d",
		       info->name, device_count[idx]++);
	if (ret < 0 || ret >= sizeof(new_name)) {
		dev_err(&pdev->dev, "failed to generate new device name\n");
		return -ENOENT;
	}

	ret = device_rename(&pdev->dev, new_name);
	if (ret) {
		dev_err(&pdev->dev, "failed to rename device to %s: %d\n",
			new_name, ret);
		return ret;
	}
	pdev->name = pdev->dev.kobj.name;

	return 0;
}

static int ummu_config_update(struct platform_device *pdev,
			      struct ummu_node *ummu_node,
			      enum ubrt_node_type type)
{
	const struct ummu_type_info *info = ummu_get_type_info(type);
	int ret;

	if (!info)
		return -EINVAL;

	if (!pdev->dev.msi.domain)
		dev_warn(&pdev->dev, "can't find device msi domain.\n");

	ret = ummu_rename_device(pdev, info);
	if (ret)
		return ret;

	ret = ummu_set_proximity(&pdev->dev, ummu_node);
	if (ret) {
		dev_err(&pdev->dev, "ummu set proximity failed ret[%d]\n", ret);
		return ret;
	}

	ret = ummu_add_resources(pdev, ummu_node, type);
	if (ret) {
		dev_err(&pdev->dev, "ummu add resources failed ret[%d]\n", ret);
		return ret;
	}

	if (type == UBRT_UMMU) {
		ret = platform_device_add_data(pdev, ummu_node->vendor_info,
					       sizeof(ummu_node->vendor_info));
		if (ret)
			return ret;
	}

	return 0;
}

#ifdef CONFIG_ACPI
static acpi_status acpi_processor_ummu(acpi_handle handle, u32 lvl,
				       void *context, void **rv)
{
	struct platform_device *pdev;
	struct acpi_device *adev;
	enum ubrt_node_type type;
	struct ummu_node *node;
	struct ubrt_fwnode *fw;
	unsigned long long uid;
	acpi_status status;
	struct device *dev;
	u64 *node_flag;
	u32 index;
	int ret;

	node_flag = context;
	index = FIELD_GET(UMMU_INDEX_MASK, *node_flag);
	type = FIELD_GET(UMMU_TYPE_MASK, *node_flag);
	fw = ubrt_fwnode_get_by_idx(index, type);
	if (!fw) {
		pr_err("can not get ubrt fwnode for index=%u, type=%d\n", index, type);
		return AE_CTRL_FALSE;
	}

	status = acpi_evaluate_integer(handle, "_UID", NULL, &uid);
	if (ACPI_FAILURE(status)) {
		pr_err("can not get dsdt uid. status[%u]\n", status);
		return AE_CTRL_TERMINATE;
	}

	if (index != (u32)uid)
		return AE_OK;

	adev = acpi_get_acpi_dev(handle);
	if (!adev) {
		pr_err("acpi get device failed\n");
		return AE_CTRL_TERMINATE;
	}

	dev = bus_find_device_by_acpi_dev(&platform_bus_type, adev);
	if (!dev) {
		pr_err("platform device not found\n");
		status = AE_CTRL_TERMINATE;
		goto out;
	}
	pdev = to_platform_device(dev);
	node = (struct ummu_node *)fw->ubrt_node;

	ret = ummu_config_update(pdev, node, type);
	if (ret) {
		dev_err(dev, "update config failed, ret[%d]\n", ret);
		put_device(dev);
		status = AE_CTRL_FALSE;
		goto out;
	}

	ret = ubrt_fwnode_set(index, type, dev->fwnode);
	if (ret) {
		dev_err(dev, "update fwnode failed, ret[%d]\n", ret);
		put_device(dev);
		status = AE_CTRL_FALSE;
	}

out:
	acpi_put_acpi_dev(adev);
	return status;
}

static int acpi_update_ummu_config(struct ummu_node *ummu_node, u32 index)
{
	acpi_status status;
	u64 node_flag;
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ummu_types); i++) {
		ret = ubrt_fwnode_add(ummu_node, index, sizeof(*ummu_node),
				      ummu_types[i].type);
		if (ret) {
			pr_err("failed to add fwnode for type %d, ret[%d]\n",
			       ummu_types[i].type, ret);
			goto rollback;
		}

		node_flag = index | ((u64)ummu_types[i].type << SZ_32);

		status = acpi_get_devices(ummu_types[i].acpi_hid,
					  acpi_processor_ummu,
					  &node_flag, NULL);
		if (ACPI_FAILURE(status)) {
			pr_err("acpi get devices error for type %d, status[%u]\n",
			       ummu_types[i].type, status);
			ubrt_fwnode_del(index, ummu_types[i].type);
			ret = -ENODEV;
			goto rollback;
		}
	}

	return 0;

rollback:
	while (--i >= 0)
		ubrt_fwnode_del(index, ummu_types[i].type);
	return ret;
}
#else
static inline int acpi_update_ummu_config(struct ummu_node *ummu_node, u32 index)
{
	return -ENODEV;
}
#endif /* CONFIG_ACPI */

#ifdef CONFIG_OF
static struct platform_device *ummu_of_find_plat_dev(struct device_node *dn,
						     u32 index)
{
	struct platform_device *pdev;
	u32 dn_index;
	int ret;

	ret = of_property_read_u32(dn, "index", &dn_index);
	if (ret) {
		pr_err("dts can't find ummu ctl-no\n");
		return NULL;
	}

	if (dn_index != index) {
		pr_debug("ummu dts_index %u != index %u\n", dn_index, index);
		return NULL;
	}

	pdev = of_find_device_by_node(dn);
	if (!pdev)
		pr_err("failed to find platform device for node: %s\n",
		       of_node_full_name(dn));

	return pdev;
}

static int ummu_of_update_config(struct platform_device *pdev,
				 struct ummu_node *ummu_node,
				 u32 index,
				 enum ubrt_node_type type)
{
	int ret;

	ret = ubrt_fwnode_add(ummu_node, index, sizeof(*ummu_node), type);
	if (ret) {
		dev_err(&pdev->dev, "failed to add ummu fwnode! ret[%d]\n", ret);
		return ret;
	}

	ret = ubrt_fwnode_set(index, type, pdev->dev.fwnode);
	if (ret) {
		dev_err(&pdev->dev, "update fwnode failed, ret[%d]\n", ret);
		goto err;
	}

	ret = ummu_config_update(pdev, ummu_node, type);
	if (ret) {
		dev_err(&pdev->dev, "update config failed, ret[%d]\n", ret);
		goto err;
	}

	return 0;
err:
	ubrt_fwnode_del(index, type);
	return ret;
}

static int of_update_ummu_config(struct ummu_node *ummu_node, u32 index)
{
	struct platform_device *pdev;
	struct device_node *dn;
	int ret, i;

	for (i = 0; i < (int)ARRAY_SIZE(ummu_types); i++) {
		for_each_compatible_node(dn, NULL, ummu_types[i].of_compat) {
			pdev = ummu_of_find_plat_dev(dn, index);
			if (!pdev)
				continue;

			ret = ummu_of_update_config(pdev, ummu_node, index,
						    ummu_types[i].type);
			if (ret)
				goto rollback;
		}
	}

	return 0;

rollback:
	while (--i >= 0)
		ubrt_fwnode_del(index, ummu_types[i].type);
	return ret;
}
#else
static inline int of_update_ummu_config(struct ummu_node *ummu_node, u32 index)
{
	return -ENODEV;
}
#endif  /* CONFIG_OF */

static int parse_ummu(void *info_node)
{
	struct ummu_sub_table *sub_table = (struct ummu_sub_table *)info_node;
	struct ummu_node *ummu_node;
	int ret;
	u32 index;

	if (!sub_table->count) {
		pr_warn("info table has no ummu.\n");
		return 0;
	}

	pr_info("ummu node num: %u\n", sub_table->count);

	ummu_node = (struct ummu_node *)sub_table->node_data;
	for (index = 0; index < sub_table->count; index++, ummu_node++) {
		if (firmware_mode == ACPI)
			ret = acpi_update_ummu_config(ummu_node, index);
		else
			ret = of_update_ummu_config(ummu_node, index);

		if (ret) {
			pr_err("Create No.%u ummu failed, ret=%d\n", index, ret);
			return ret;
		}
	}

	return 0;
}

int handle_ummu_table(u64 pointer)
{
	void *info_node = ub_table_get(pointer);
	int ret;

	if (!info_node)
		return -EINVAL;

	ret = parse_ummu(info_node);
	ub_table_put(info_node);
	return ret;
}
