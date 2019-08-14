/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_PRIV_PHY_H__
#define __HNS3_PRIV_PHY_H__

struct phy_reg_param {
	u16 operate;
	u16 page_select_addr;
	u16 page;
	u32 addr;
	u16 data;
};

int hns3_test_phy_register_cfg(struct hns3_nic_priv *net_priv,
			       void *buf_in, u16 in_size,
			       void *buf_out, u16 *out_size);

#endif
