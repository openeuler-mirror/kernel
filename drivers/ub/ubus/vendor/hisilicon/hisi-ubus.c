// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#include <linux/module.h>
#include <linux/platform_device.h>

#include "../../ubus.h"
#include "local-ras.h"
#include "hisi-ubus.h"

int msg_wait = 1024;
module_param(msg_wait, int, 0444);
MODULE_PARM_DESC(msg_wait, "message wait timeout, default: 1024ms");

#define HISI_VENDOR_ID 0xCC08
#define HISI_UBUS_DRV_NAME "hisi_ubus"

static const struct ub_manage_subsystem_ops hisi_ub_manage_subsystem_ops = {
	.vendor = HISI_VENDOR_ID,
	.controller_probe = ub_bus_controller_probe,
	.controller_remove = ub_bus_controller_remove,
	.ras_handler_probe = ub_ras_handler_probe,
	.ras_handler_remove = ub_ras_handler_remove
};

static const struct of_device_id hisi_ubus_of_match[] = {
	{ .compatible = "hisi,ubus", },
	{}
};
MODULE_DEVICE_TABLE(of, hisi_ubus_of_match);

static const struct acpi_device_id hisi_ubus_acpi_match[] = {
	{ "HISI0581", 0 },
	{}
};
MODULE_DEVICE_TABLE(acpi, hisi_ubus_acpi_match);

static struct platform_driver hisi_ubus_driver = {
	.driver = {
		.name = HISI_UBUS_DRV_NAME,
		.of_match_table = hisi_ubus_of_match,
		.acpi_match_table = hisi_ubus_acpi_match,
	},
};

static int __init hisi_ubus_driver_register(struct platform_driver *drv)
{
	int ret;

	ret = register_ub_manage_subsystem_ops(&hisi_ub_manage_subsystem_ops);
	if (ret)
		return ret;

	ret = platform_driver_register(drv);
	if (ret)
		goto platform_driver_register_fail;

	return 0;

platform_driver_register_fail:
	unregister_ub_manage_subsystem_ops(&hisi_ub_manage_subsystem_ops);
	return ret;
}

static void __exit hisi_ubus_driver_unregister(struct platform_driver *drv)
{
	platform_driver_unregister(drv);
	unregister_ub_manage_subsystem_ops(&hisi_ub_manage_subsystem_ops);
}

/*
 * Ensure the ummu driver is loaded before the ub device appears if the device
 * driver plans to use ummu as the iommu implementation, so that
 * ub_bus_type_iommu_ops can be set by ummu driver before it will be called.
 *
 * If the ummu driver is not there that's OK as well.
 */
MODULE_SOFTDEP("pre: ummu");
module_driver(hisi_ubus_driver, hisi_ubus_driver_register, hisi_ubus_driver_unregister);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Hisilicon UnifiedBus Manage Subsystem");
MODULE_IMPORT_NS(UB_UBUS);
