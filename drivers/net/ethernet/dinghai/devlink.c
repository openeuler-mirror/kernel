// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#include <linux/dinghai/devlink.h>
#include <linux/dinghai/driver.h>

s32 zxdh_devlink_register(struct devlink *devlink)
{
	struct dh_core_dev *dh_dev = devlink_priv(devlink);
	s32 err = 0;

	devlink_register(devlink);

	err = dh_dev->devlink_ops->params_register(devlink);
	if (err != 0) {
		LOG_ERR("params_register failed: %d\n", err);
		return err;
	}

	return err;
}

struct devlink *zxdh_devlink_alloc(struct device *dev, struct devlink_ops *dh_devlink_ops,
				   size_t priv_size)
{
	return devlink_alloc(dh_devlink_ops, sizeof(struct dh_core_dev) + priv_size, dev);
}

void zxdh_devlink_free(struct devlink *devlink)
{
	devlink_free(devlink);
}

void zxdh_devlink_unregister(struct devlink *devlink)
{
	struct dh_core_dev *dev = devlink_priv(devlink);

	dev->devlink_ops->params_unregister(devlink);

	devlink_unregister(devlink);
}
