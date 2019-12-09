/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_RSS_H
#define __HNS3_CAE_RSS_H

#define RSS_HASH_KEY_NUM		40

struct rss_config {
	u8 hash_config;
	u8 rsv[7];
	u8 hash_key[RSS_HASH_KEY_NUM];
	u8 is_read;
};

int hns3_cae_rss_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size,
		     void *buf_out, u32 out_size);

#endif
