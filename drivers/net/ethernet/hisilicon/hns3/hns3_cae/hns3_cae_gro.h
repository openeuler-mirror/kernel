/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_GRO_H__
#define __HNS3_CAE_GRO_H__

#define GRO_AGE_RESV_LEN 20

struct hns3_cae_gro_age_config_cmd {
	u32 ppu_gro_age_cnt;
	u8 rsv[GRO_AGE_RESV_LEN];
};

struct gro_param {
	u8 is_read;
	u32 age_cnt;
};

int hns3_gro_age_handle(const struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size);
int hns3_gro_dump_bd_buff_size(const struct hns3_nic_priv *net_priv,
			       void *buf_in, u32 in_size, void *buf_out,
			       u32 out_size);
#endif
