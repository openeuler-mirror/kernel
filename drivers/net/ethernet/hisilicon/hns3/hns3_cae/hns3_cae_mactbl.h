/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_MACTBL_H__
#define __HNS3_CAE_MACTBL_H__

enum hns3_mac_table_code {
	HNS3_MACTBL_OPT_TABLE_LOOKUP,
	HNS3_MACTBL_OPT_TABLE_ADD,
	HNS3_MACTBL_OPT_TABLE_DEL,
};

enum hns3_mac_result_code {
	HNS3_MACTBL_RESULT_SUCCESS,
	HNS3_MACTBL_RESULT_FAIL,
	HNS3_MACTBL_RESULT_NOEXIST,
	HNS3_MACTBL_RESULT_NOSPACE
};

struct hns3_mac_tbl_para {
	u8 op_cmd;
	u8 mac_addr[6];
	u8 result;
};

int hns3_cae_opt_mactbl(struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size);

#endif
