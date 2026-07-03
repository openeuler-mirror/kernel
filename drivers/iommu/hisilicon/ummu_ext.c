// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 * Description: HISI UMMU private extensions for the UMMU Framework.
 */

#define pr_fmt(fmt) "[UMMU][HISI_PRIV]: " fmt
#include <linux/module.h>
#include <linux/sizes.h>
#include <ub/ubus/ubus.h>

/* Indicates whether to allow permission table space expansion. */
static bool ummu_mapt_blk_exp __read_mostly = true;

/* the basic block's size of the permission table is 64KB */
static size_t ummu_mapt_base_blk_size __read_mostly = SZ_64K;

#ifdef CONFIG_UB_UMMU_BYPASSDEV

struct ummu_bypass_device  {
	u32 vendor;
	u32 device;
};
#define MAX_CMDLINE_UMMU_BYPASSDEV ((u8)16)
#define MAX_VENDOR 0xFFFFU
#define MAX_DEVICE 0xFFFFU

static struct ummu_bypass_device bypass_dev[MAX_CMDLINE_UMMU_BYPASSDEV];
static u8 bypass_dev_num;

static int __init ummu_bypass_dev_setup(char *str)
{
	u32 device;
	u32 vendor;
	int ret;

	if (!str)
		return -EINVAL;

	ret = sscanf(str, "%i:%i", &vendor, &device);
	if (ret != 2 || vendor > MAX_VENDOR || device > MAX_DEVICE) {
		pr_warn("Invalid ummu bypass dev param!\n");
		return -EINVAL;
	}

	if (bypass_dev_num >= MAX_CMDLINE_UMMU_BYPASSDEV) {
		pr_warn("Too many ummu bypass dev params!\n");
		return -ERANGE;
	}

	bypass_dev[bypass_dev_num].vendor = vendor;
	bypass_dev[bypass_dev_num].device = device;
	bypass_dev_num++;

	return 0;
}

__setup("ummu.bypassdev=", ummu_bypass_dev_setup);

int ummu_bypass_dev_domain_type(struct device *dev)
{
	struct ub_entity *uent;
	u8 i;

	if (!dev_is_ub(dev))
		return 0;

	uent = to_ub_entity(dev);
	for (i = 0; i < bypass_dev_num; i++) {
		if (uent_vendor(uent) == bypass_dev[i].vendor &&
		    uent_device(uent) == bypass_dev[i].device) {
			return IOMMU_DOMAIN_IDENTITY;
		}
	}

	return 0;
}
EXPORT_SYMBOL_NS_GPL(ummu_bypass_dev_domain_type, UMMU_INTERNAL);
#endif

static int __init ummu_mapt_blk_expan_setup(char *str)
{
	int ret = kstrtobool(str, &ummu_mapt_blk_exp);

	if (!ret)
		pr_info("the expansion capability of the ummu mapt block is %s.\n",
			ummu_mapt_blk_exp ? "on" : "off");
	return ret;
}
early_param("ummu.mapt_exp", ummu_mapt_blk_expan_setup);

bool ummu_get_mapt_blk_exp(void)
{
	return ummu_mapt_blk_exp;
}
EXPORT_SYMBOL_NS_GPL(ummu_get_mapt_blk_exp, UMMU_INTERNAL);

static int __init ummu_mapt_base_blk_size_setup(char *p)
{
	ummu_mapt_base_blk_size = memparse(p, &p);
	if (ummu_mapt_base_blk_size == 0 || ummu_mapt_base_blk_size > SZ_2M)
		ummu_mapt_base_blk_size = SZ_64K;
	pr_info("the ummu mapt block expansion size 0x%lx.\n",
		ummu_mapt_base_blk_size);
	return 0;
}
early_param("ummu.mapt_base_size", ummu_mapt_base_blk_size_setup);

size_t ummu_get_mapt_base_blk_size(void)
{
	return ummu_mapt_base_blk_size;
}
EXPORT_SYMBOL_NS_GPL(ummu_get_mapt_base_blk_size, UMMU_INTERNAL);
