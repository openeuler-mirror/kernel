// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus eu: " fmt

#include <linux/dma-mapping.h>

#include "ubus.h"
#include "ubus_controller.h"
#include "eu.h"

/*
 * The ubus driver provides only the eid-upi table memory.
 * The table configuration policy is developed by the vendor.
 * Implemented in a unified manner in the future.
 */

static int ub_eu_table_init_common(struct ub_entity *uent)
{
	struct ub_bus_controller *ubc = uent->ubc;
	struct ub_eu_table *eu;
	u32 entries, cfg_ret;
	int ret;

	ret = ub_cfg_read_dword(uent, UB_EU_TEN, &entries);
	if (ret) {
		ub_err(uent, "EU TABLE get failed, ret=%d\n", ret);
		return ret;
	}
	if (entries == 0) {
		ub_err(uent, "EID-UPI Table Entry Num is 0\n");
		return -EINVAL;
	}

	ub_info(uent, "EU TABLE entries num is %#x\n", entries);

	eu = kzalloc(sizeof(*eu), GFP_KERNEL);
	if (!eu)
		return -ENOMEM;

	eu->entries = entries;
	eu->size = entries * EU_ENTRY_SIZE;
	eu->addr = dma_alloc_coherent(&ubc->dev, eu->size, &eu->dma_addr,
				      GFP_KERNEL);
	if (!eu->addr) {
		ret = -ENOMEM;
		goto free;
	}

	cfg_ret = (u32)ub_cfg_write_dword(uent, UB_EU_TBA_L,
				 lower_32_bits(eu->dma_addr));
	cfg_ret |= (u32)ub_cfg_write_dword(uent, UB_EU_TBA_H,
				  upper_32_bits(eu->dma_addr));
	if (cfg_ret) {
		ret = (int)cfg_ret;
		ub_err(uent, "EU TABLE set failed, ret=%d\n", ret);
		(void)ub_cfg_write_dword(uent, UB_EU_TBA_L, 0);
		(void)ub_cfg_write_dword(uent, UB_EU_TBA_H, 0);
		goto dma_free;
	}

	memset(eu->addr, 0, eu->size);
	uent->eu_table = eu;

	return 0;

dma_free:
	dma_free_coherent(&ubc->dev, eu->size, eu->addr, eu->dma_addr);
free:
	kfree(eu);
	return ret;
}

static void ub_eu_table_uninit_common(struct ub_entity *uent)
{
	struct ub_eu_table *eu = uent->eu_table;
	struct ub_bus_controller *ubc = uent->ubc;
	u32 ret;

	uent->eu_table = NULL;

	ret = (u32)ub_cfg_write_dword(uent, UB_EU_TBA_L, 0);
	ret |= (u32)ub_cfg_write_dword(uent, UB_EU_TBA_H, 0);
	if (ret)
		ub_err(uent, "EU TABLE unset failed, ret=%d\n", (int)ret);

	dma_free_coherent(&ubc->dev, eu->size, eu->addr, eu->dma_addr);
	kfree(eu);
}

void ub_eu_table_init(struct ub_entity *uent)
{
	struct ub_bus_controller *ubc = uent->ubc;
	int ret;

	if (!is_ibus_controller(uent) || ubc->cluster)
		return;

	ret = ub_eu_table_init_common(uent);
	if (ret)
		return;

	if (ubc->ops && ubc->ops->eu_table_init) {
		ret = ubc->ops->eu_table_init(ubc);
		if (ret) {
			ub_err(uent, "EU TABLE private init failed, ret=%d\n",
			       ret);
			goto uninit_common;
		}
	}

	ub_cfg_write_byte(uent, UB_TH_EN, 1);

	return;

uninit_common:
	ub_eu_table_uninit_common(uent);
}

void ub_eu_table_uninit(struct ub_entity *uent)
{
	struct ub_bus_controller *ubc = uent->ubc;

	if (!uent->eu_table)
		return;

	ub_cfg_write_byte(uent, UB_TH_EN, 0);

	if (ubc->ops && ubc->ops->eu_table_uninit)
		ubc->ops->eu_table_uninit(ubc);

	ub_eu_table_uninit_common(uent);
}

int ub_cfg_eu_table(struct ub_bus_controller *ubc, bool flag, u32 eid, u16 upi)
{
	struct ub_bus_controller_ops *ops = ubc->ops;
	int ret;

	if (ubc->cluster)
		return 0;

	if (!ops || !ops->eu_cfg)
		return -ENODEV;

	ret = ops->eu_cfg(ubc, flag, eid, upi);
	if (ret)
		dev_err(&ubc->dev, "eu %s fail, eid[%#05x]<->upi[%#04x]\n",
			flag ? "add" : "del", eid, upi);

	return ret;
}
