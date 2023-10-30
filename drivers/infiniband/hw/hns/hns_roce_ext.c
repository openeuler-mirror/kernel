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

static bool is_hns_roce_vf(struct hns_roce_dev *hr_dev)
{
	return hr_dev->is_vf;
}

bool rdma_support_stars(struct ib_device *ib_dev)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	if (!is_hns_roce(ib_dev) || is_hns_roce_vf(hr_dev))
		return false;

	if (poe_is_supported(hr_dev))
		return true;

	return false;
}
EXPORT_SYMBOL(rdma_support_stars);

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

u64 rdma_query_qp_db(struct ib_device *ib_dev, int qp_index)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);
	u64 bar_addr;

	if (!rdma_support_stars(ib_dev))
		return 0;

	bar_addr = pci_resource_start(hr_dev->pci_dev, HNS_ROCE_MEM_BAR);
	return bar_addr + hr_dev->sdb_offset +
		DB_REG_OFFSET * hr_dev->priv_uar.index;
}
EXPORT_SYMBOL(rdma_query_qp_db);

int rdma_query_hw_id(struct ib_device *ib_dev, u32 *chip_id,
		     u32 *die_id, u32 *func_id)
{
	struct hns_roce_dev *hr_dev = to_hr_dev(ib_dev);

	if (!is_hns_roce(ib_dev) || is_hns_roce_vf(hr_dev))
		return -EOPNOTSUPP;

	if (!chip_id || !die_id || !func_id)
		return -EINVAL;

	if (hr_dev->chip_id == HNS_IB_INVALID_ID)
		return -EINVAL;

	*chip_id = hr_dev->chip_id;
	*die_id = hr_dev->die_id;
	*func_id = hr_dev->func_id;
	return 0;
}
EXPORT_SYMBOL(rdma_query_hw_id);

