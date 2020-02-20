/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_HILINK_PARAM_H__
#define __HNS3_CAE_HILINK_PARAM_H__

#define HILINK_LANE_MAX_NUM		10

#define HCLGE_OPC_DUMP_CTLE_PARAM	0x0382
#define HCLGE_OPC_DUMP_DFE_PARAM	0x0383
#define HCLGE_OPC_DUMP_FFE_PARAM	0x0384

struct hns3_ctle_data {
	u8 ctlebst[3];
	u8 ctlecmband[3];
	u8 ctlermband[3];
	u8 ctleza[3];
	u8 ctlesqh[3];
	u8 ctleactgn[3];
	u8 ctlepassgn;
	u8 ctlerefsel;
	u8 ctleibiastune;
	u8 alos;
	u8 lpbk;
};

struct hns3_dfe_data {
	u8 dfefxtap[10];	/* DFE Fix Tap */
	u8 floatingtap[6];	/* DFE Floating Taps */
};

struct hns3_ffe_data {
	u8 pre2;
	u8 pre1;
	u8 main;
	u8 post1;
	u8 post2;
};

struct hns3_hilink_param {
	u32 lane_start;
	u32 lane_len;
	struct hns3_ctle_data ctle_param[HILINK_LANE_MAX_NUM];
	struct hns3_dfe_data dfe_param[HILINK_LANE_MAX_NUM];
	struct hns3_ffe_data ffe_param[HILINK_LANE_MAX_NUM];
};

int hns3_get_hilink_param(const struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size);

#endif
