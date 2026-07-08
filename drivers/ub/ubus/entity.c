// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <ub/ubus/ubus.h>

int ub_get_dst_eid(struct ub_entity *dev)
{
	struct ub_bus_controller *ubc;
	u32 eid;

	if (!dev)
		return -EINVAL;

	ubc = dev->ubc;

	if (!ubc)
		return -ENODEV;

	eid = ubc->uent->eid;
	if (dev->bi)
		eid = dev->bi->info.eid;

	return eid;
}
EXPORT_SYMBOL_GPL(ub_get_dst_eid);
