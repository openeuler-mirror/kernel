// SPDX-License-Identifier: GPL-2.0
/* Huawei UDMA Linux driver
 * Copyright (c) 2023-2023 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 */

#include "hns3_udma_device.h"
#include "urma/ubcore_api.h"
#include "hns3_udma_device.h"

static struct ubcore_ops g_udma_dev_ops = {

};

static void udma_set_devname(struct udma_dev *udma_dev,
			     struct ubcore_device *ub_dev)
{
	scnprintf(udma_dev->dev_name, UBCORE_MAX_DEV_NAME, "udma%d",
		  udma_dev->func_id);
	dev_info(udma_dev->dev, "Set dev_name %s\n", udma_dev->dev_name);
	strlcpy(ub_dev->dev_name, udma_dev->dev_name, UBCORE_MAX_DEV_NAME);
}

static int udma_register_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = NULL;
	struct udma_netdev *uboe = NULL;

	ub_dev = &udma_dev->ub_dev;
	uboe = &udma_dev->uboe;
	spin_lock_init(&uboe->lock);
	ub_dev->transport_type = UBCORE_TRANSPORT_IB;
	ub_dev->ops = &g_udma_dev_ops;
	ub_dev->dev.parent = udma_dev->dev;
	ub_dev->dma_dev = ub_dev->dev.parent;
	ub_dev->netdev = udma_dev->uboe.netdevs[0];
	scnprintf(ub_dev->ops->driver_name, UBCORE_MAX_DRIVER_NAME, "udma_v1");
	udma_set_devname(udma_dev, ub_dev);
	ub_dev->num_comp_vectors = udma_dev->irq_num;

	return ubcore_register_device(ub_dev);
}

static void udma_unregister_device(struct udma_dev *udma_dev)
{
	struct ubcore_device *ub_dev = &udma_dev->ub_dev;

	ubcore_unregister_device(ub_dev);
}

int udma_hnae_client_init(struct udma_dev *udma_dev)
{
	struct device *dev = udma_dev->dev;
	int ret;

	ret = udma_dev->hw->cmq_init(udma_dev);
	if (ret) {
		dev_err(dev, "Init UB Command Queue failed!\n");
		goto error_failed_cmq_init;
	}

	ret = udma_dev->hw->hw_profile(udma_dev);
	if (ret) {
		dev_err(dev, "Get UB engine profile failed!\n");
		goto error_failed_hw_profile;
	}

	ret = udma_cmd_init(udma_dev);
	if (ret) {
		dev_err(dev, "cmd init failed!\n");
		goto error_failed_cmd_init;
	}

	if (udma_dev->cmd_mod) {
		ret = udma_cmd_use_events(udma_dev);
		if (ret) {
			udma_dev->cmd_mod = 0;
			dev_warn(dev,
				 "Cmd event mode failed, set back to poll!\n");
		}
	}

	ret = udma_dev->hw->hw_init(udma_dev);
	if (ret) {
		dev_err(dev, "hw_init failed!\n");
		goto error_failed_engine_init;
	}

	ret = udma_register_device(udma_dev);
	if (ret) {
		dev_err(dev, "udma register device failed!\n");
		goto error_failed_register_device;
	}

	return 0;

error_failed_register_device:
	udma_dev->hw->hw_exit(udma_dev);

error_failed_engine_init:
error_failed_cmd_init:
error_failed_hw_profile:
	udma_dev->hw->cmq_exit(udma_dev);

error_failed_cmq_init:
	return ret;
}

void udma_hnae_client_exit(struct udma_dev *udma_dev)
{
	udma_unregister_device(udma_dev);

	if (udma_dev->hw->hw_exit)
		udma_dev->hw->hw_exit(udma_dev);
	if (udma_dev->hw->cmq_exit)
		udma_dev->hw->cmq_exit(udma_dev);
}
