// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#define pr_fmt(fmt)	"ubus controller: " fmt

#include <linux/acpi.h>

#include "ubus.h"
#include "ubus_controller.h"

int ub_ubc_to_node(struct ub_bus_controller *ubc)
{
	return dev_to_node(&ubc->dev);
}

void ub_bus_controllers_remove(void)
{
	const struct ub_manage_subsystem_ops *manage_subsystem_ops;
	struct ub_bus_controller *ubc;

	manage_subsystem_ops = get_ub_manage_subsystem_ops();
	if (!manage_subsystem_ops || !manage_subsystem_ops->controller_remove)
		return;

	list_for_each_entry_reverse(ubc, &ubc_list, node)
		if (ubc->ops)
			manage_subsystem_ops->controller_remove(ubc);
}

int ub_bus_controllers_probe(void)
{
	const struct ub_manage_subsystem_ops *manage_subsystem_ops;
	struct ub_bus_controller *ubc;
	int ret;

	manage_subsystem_ops = get_ub_manage_subsystem_ops();
	if (!manage_subsystem_ops || !manage_subsystem_ops->controller_probe)
		return -EINVAL;

	list_for_each_entry(ubc, &ubc_list, node) {
		ret = manage_subsystem_ops->controller_probe(ubc);
		if (ret)
			goto out;
	}

	return 0;
out:
	ub_bus_controllers_remove();
	return ret;
}

unsigned long long ub_feature_get(void)
{
	const struct ub_manage_subsystem_ops *manage_subsystem_ops;

	manage_subsystem_ops = get_ub_manage_subsystem_ops();
	if (!manage_subsystem_ops || !manage_subsystem_ops->feature_get)
		return U64_MAX;

	return manage_subsystem_ops->feature_get();
}
EXPORT_SYMBOL_GPL(ub_feature_get);

struct ub_bus_controller *ub_find_bus_controller_by_cna(u32 cna)
{
	struct ub_bus_controller *ubc;

	if (!get_ub_manage_subsystem_ops()) {
		pr_err("manage subsystem ops is null\n");
		return NULL;
	}

	list_for_each_entry(ubc, &ubc_list, node)
		if (ubc->uent->cna == cna)
			return ubc;

	return NULL;
}
