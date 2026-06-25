// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#define dev_fmt(fmt) "unic: (pid %d) " fmt, current->pid

#include <net/rtnetlink.h>
#include <linux/auxiliary_bus.h>
#include <linux/module.h>

#include "debugfs/unic_debugfs.h"
#include "unic_dev.h"
#include "unic_netdev.h"

static int unic_probe(struct auxiliary_device *adev,
		      const struct auxiliary_device_id *id)
{
	struct unic_dev *unic_dev;
	int ret;

	ret = unic_dev_init(adev);
	if (ret) {
		ubase_adev_fault_log(adev, UNIC_FAULT_EVENT_ID_PROBE, NULL);
		dev_err(adev->dev.parent,
			"failed to init unic dev, ret = %d.\n", ret);
		return ret;
	}

	unic_dev = (struct unic_dev *)dev_get_drvdata(&adev->dev);
	ret = unic_dbg_init(adev);
	if (ret) {
		unic_err(unic_dev,
			 "failed to init unic debugfs, ret = %d.\n", ret);
		unic_dev_uninit(adev);
		return ret;
	}

	set_bit(UNIC_STATE_INITED, &unic_dev->state);
	ubase_update_adev_status(adev, 0);

	return 0;
}

static void unic_remove(struct auxiliary_device *adev)
{
#define UNIC_RESET_WAIT_TIME	100

	struct unic_dev *unic_dev = (struct unic_dev *)dev_get_drvdata(&adev->dev);

	while (test_and_set_bit(UNIC_STATE_DISABLED, &unic_dev->state))
		msleep(UNIC_RESET_WAIT_TIME);

	set_bit(UNIC_STATE_REMOVING, &unic_dev->state);

	unic_info(unic_dev, "unic remove start.\n");

	unic_dbg_uninit(adev);
	unic_dev_uninit(adev);
}

static const struct auxiliary_device_id unic_id_table[] = {
	{
		.name = UBASE_ADEV_NAME ".unic",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, unic_id_table);

static struct auxiliary_driver unic_drv = {
	.probe = unic_probe,
	.remove = unic_remove,
	.name = "unic",
	.driver = {
		.probe_type = PROBE_FORCE_SYNCHRONOUS,
	},
	.id_table = unic_id_table,
};

static int __init unic_init(void)
{
	int ret;

	ret = unic_init_wq();
	if (ret) {
		pr_err("unic: failed to create workqueue.\n");
		return ret;
	}

	ret = unic_register_ipaddr_notifier();
	if (ret)
		goto err_reg_ip_notifier;

	ret = unic_register_netdevice_notifier();
	if (ret)
		goto err_reg_netdev_notifier;

	ret = auxiliary_driver_register(&unic_drv);
	if (ret)
		goto err_aux_reg;

	return ret;

err_aux_reg:
	unic_unregister_netdevice_notifier();
err_reg_netdev_notifier:
	unic_unregister_ipaddr_notifier();
err_reg_ip_notifier:
	unic_destroy_wq();
	return ret;
}

static void __exit unic_exit(void)
{
	unic_unregister_netdevice_notifier();
	unic_unregister_ipaddr_notifier();
	auxiliary_driver_unregister(&unic_drv);
	unic_destroy_wq();
}

module_init(unic_init);
module_exit(unic_exit);

MODULE_DESCRIPTION("UNIC: Hisilicon Network Driver");
MODULE_AUTHOR("Huawei Tech. Co., Ltd.");
MODULE_LICENSE("GPL");
MODULE_VERSION(UNIC_MOD_VERSION);
