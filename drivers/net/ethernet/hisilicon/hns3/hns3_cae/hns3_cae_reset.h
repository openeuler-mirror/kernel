/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2015-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_RESET_H__
#define __HNS3_CAE_RESET_H__

struct reset_param {
	u32 reset_level;
};

struct tx_timeout_param {
	u16 wr_flag;
	u16 tx_timeout_size;
};

int hns3_cae_nic_reset(const struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size, void *buf_out,
		       u32 out_size);
int hns3_cae_nic_timeout_cfg(const struct hns3_nic_priv *net_priv,
			     void *buf_in, u32 in_size,
			     void *buf_out, u32 out_size);

#endif
