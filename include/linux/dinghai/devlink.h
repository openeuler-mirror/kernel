/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_DEVLINK_H__
#define __ZXDH_DEVLINK_H__

#include <net/devlink.h>
#include <linux/dinghai/driver.h>
#include <linux/types.h>

struct devlink *zxdh_devlink_alloc(struct device *dev, struct devlink_ops *dh_devlink_ops,
				   size_t priv_size);
void zxdh_devlink_free(struct devlink *devlink);

int32_t zxdh_devlink_register(struct devlink *devlink);

void zxdh_devlink_unregister(struct devlink *devlink);

static inline struct net *dh_core_net(struct dh_core_dev *dev)
{
	return devlink_net(priv_to_devlink(dev));
}

#endif
