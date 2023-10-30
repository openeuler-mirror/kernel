// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
/*
 * Copyright (c) 2023 Hisilicon Limited. All rights reserved.
 */

#include <rdma/ib_user_verbs.h>
#include <rdma/ib_verbs.h>
#include <rdma/uverbs_types.h>
#include <rdma/uverbs_ioctl.h>
#include <rdma/ib_umem.h>
#include "hns_roce_device.h"

static int hns_roce_config_poe_ch(struct hns_roce_dev *hr_dev, u32 index,
				  u64 poe_addr)
{
	int ret;

	if (!hr_dev->hw->cfg_poe_ch) {
		ibdev_err_ratelimited(&hr_dev->ib_dev,
			"configure POE channel has not been supported in this device.\n");
		return -EOPNOTSUPP;
	}

	ret = hr_dev->hw->cfg_poe_ch(hr_dev, index, poe_addr);
	if (ret)
		ibdev_err_ratelimited(&hr_dev->ib_dev,
			"configure POE channel %u failed, ret = %d.\n",
			index, ret);

	return ret;
}

static bool check_poe_in_use(struct hns_roce_poe_ch *poe_ch)
{
	return poe_ch->en && refcount_read(&poe_ch->ref_cnt) > 1;
}

static void update_poe_ch(struct hns_roce_poe_ch *poe_ch, u64 poe_addr)
{
	if (poe_addr) {
		if (poe_addr != poe_ch->addr)
			refcount_set(&poe_ch->ref_cnt, 1);
	} else {
		refcount_set(&poe_ch->ref_cnt, 0);
	}
	poe_ch->en = !!poe_addr;
	poe_ch->addr = poe_addr;
}

int hns_roce_register_poe_channel(struct hns_roce_dev *hr_dev, u8 channel,
				  u64 poe_addr)
{
	struct hns_roce_poe_ch *poe_ch;
	int ret;

	if (!poe_is_supported(hr_dev))
		return -EOPNOTSUPP;

	if (channel >= hr_dev->poe_ctx.poe_num || !poe_addr)
		return -EINVAL;

	poe_ch = &hr_dev->poe_ctx.poe_ch[channel];
	if (check_poe_in_use(poe_ch))
		return -EBUSY;

	ret = hns_roce_config_poe_ch(hr_dev, channel, poe_addr);
	if (ret)
		return ret;

	update_poe_ch(poe_ch, poe_addr);

	return ret;
}

int hns_roce_unregister_poe_channel(struct hns_roce_dev *hr_dev, u8 channel)
{
	struct hns_roce_poe_ch *poe_ch;
	int ret;

	if (!poe_is_supported(hr_dev))
		return -EOPNOTSUPP;

	if (channel >= hr_dev->poe_ctx.poe_num)
		return -EINVAL;

	poe_ch = &hr_dev->poe_ctx.poe_ch[channel];
	if (check_poe_in_use(poe_ch))
		return -EBUSY;

	ret = hns_roce_config_poe_ch(hr_dev, channel, 0);
	if (ret)
		return ret;

	update_poe_ch(poe_ch, 0);

	return ret;
}
