// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <ub/ubus/ubus.h>

struct ub_bus_controller *ub_ubc_get(struct ub_bus_controller *ubc)
{
	if (ubc)
		get_device(&ubc->dev);
	return ubc;
}
EXPORT_SYMBOL_GPL(ub_ubc_get);

void ub_ubc_put(struct ub_bus_controller *ubc)
{
	if (ubc)
		put_device(&ubc->dev);
}
EXPORT_SYMBOL_GPL(ub_ubc_put);
