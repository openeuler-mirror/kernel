/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_FD_H__
#define __HNS3_CAE_FD_H__

#define HCLGE_OPC_FD_CNT_OP	0x1205

struct fd_param {
	u8 is_read;
	u8 stage;
	u16 op;
	u8 xy_sel;
	__le32 idx;
	u8 entry_vld;
	u8 data[128];

};

struct hclge_fd_cnt_op_cmd {
	u8 stage;
	u8 rsv1[3];
	__le16 cnt_idx;
	u8 rsv2[2];
	__le64 cnt_value;
	u8 rsv3[8];
};

struct hclge_fd_tcam_data {
	u8 vld;
	u8 tcam_data[52];
};

int hns3_test_fd_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size);

#endif
