// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2023 Hisilicon Limited.
 */

#include <rdma/ib_verbs.h>
#include "hns_roce_device.h"

static bool is_hns_roce(struct ib_device *ib_dev)
{
	if (ib_dev && ib_dev->ops.driver_id == RDMA_DRIVER_HNS)
		return true;

	return false;
}

int rdma_register_poe_channel(struct ib_device *ib_dev, u8 channel,
			      u64 poe_addr)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	if (!is_hns_roce(ib_dev))
		return -EOPNOTSUPP;

	return hns_roce_register_poe_channel(hr_dev, channel, poe_addr);
}
EXPORT_SYMBOL(rdma_register_poe_channel);

int rdma_unregister_poe_channel(struct ib_device *ib_dev, u8 channel)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	if (!is_hns_roce(ib_dev))
		return -EOPNOTSUPP;

	return hns_roce_unregister_poe_channel(hr_dev, channel);
}
EXPORT_SYMBOL(rdma_unregister_poe_channel);

