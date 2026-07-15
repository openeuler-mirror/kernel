// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#include <linux/auxiliary_bus.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/sched.h>

#include "ubaseproxy_dev.h"

static int ubaseproxy_probe(struct auxiliary_device *adev,
			    const struct auxiliary_device_id *id)
{
	struct ubaseproxy_dev *udev;
	int ret;

	udev = kzalloc((sizeof(*udev)), GFP_KERNEL);
	if (!udev)
		return -ENOMEM;

	udev->comdev.adev = adev;
	dev_set_drvdata(&adev->dev, udev);

	ret = ubaseproxy_dev_init(udev);
	if (ret) {
		ubaseproxy_err(udev, "failed to init ubaseproxy device, ret = %d.\n",
			       ret);
		goto err_init;
	}

	set_bit(UBASEPROXY_STATE_INITED, &udev->state);

	return 0;

err_init:
	dev_set_drvdata(&adev->dev, NULL);
	kfree(udev);

	return ret;
}

static void ubaseproxy_remove(struct auxiliary_device *adev)
{
#define UBASEPROXY_RESET_WAIT_TIME 100

	struct ubaseproxy_dev *udev = get_ubaseproxy_dev(adev);

	while (test_and_set_bit(UBASEPROXY_STATE_DISABLED, &udev->state))
		msleep(UBASEPROXY_RESET_WAIT_TIME);

	set_bit(UBASEPROXY_STATE_REMOVING, &udev->state);
	ubaseproxy_dev_uninit(udev);

	dev_set_drvdata(&adev->dev, NULL);

	kfree(udev);
}

static const struct auxiliary_device_id ubaseproxy_id_table[] = {
	{
		.name = UBASE_ADEV_NAME ".ubaseproxy",
	},
	{},
};

MODULE_DEVICE_TABLE(auxiliary, ubaseproxy_id_table);

static struct auxiliary_driver ubaseproxy_drv = {
	.probe = ubaseproxy_probe,
	.remove = ubaseproxy_remove,
	.name = "ubaseproxy",
	.id_table = ubaseproxy_id_table,
};

static int __init ubaseproxy_init(void)
{
	int ret;

	ret = auxiliary_driver_register(&ubaseproxy_drv);
	if (ret)
		pr_err("failed to register auxiliary_driver\n");

	return ret;
}

static void __exit ubaseproxy_exit(void)
{
	auxiliary_driver_unregister(&ubaseproxy_drv);
}

module_init(ubaseproxy_init);
module_exit(ubaseproxy_exit);

MODULE_DESCRIPTION("UBASEPROXY: Hisilicon UB Entity Basic Proxy Driver");
MODULE_LICENSE("GPL");
