/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_DCB_H__
#define __HNS3_CAE_DCB_H__

struct nictool_pfc_cfg_param {
	u8 is_read;
	u8 cfg_flag;
	u8 pfc_en;
	u8 prien;
	u16 pause_time;
	u8 pause_gap;
};

struct nictool_dcb_cfg_param {
	u8 is_read;
	u8 cfg_flag;
	u8 dcb_en;
};

struct nictool_ets_cfg_param {
	u8 is_read;
	u8 cfg_flag;
	u8 ets_en;
	u8 up2tc[8];
	u8 bw[8];
	u8 schedule[8];
};

struct nictool_dcb_info {
	struct hns3_nic_priv *net_priv;
	struct nictool_pfc_cfg_param pfc_cfg_info;
	struct nictool_dcb_cfg_param dcb_cfg_info;
	struct nictool_ets_cfg_param ets_cfg_info;
};

#define NICTOOL_OPC_CFG_MAC_PAUSE_EN		0x0701
#define NICTOOL_OPC_CFG_PFC_PAUSE_EN		0x0702
#define NICTOOL_OPC_CFG_PAUSE_PARAM		0x0703
#define NICTOOL_OPC_PRI_TO_TC_MAPPING		0x0709
#define NICTOOL_OPC_TM_PRI_WEIGHT		0x080b

#define NICTOOL_DCB_DCB_CFG_FLAG		0x1

#define NICTOOL_ETS_EN_CFG_FLAG			0x1
#define NICTOOL_ETS_UP2TC_CFG_FLAG		0x2
#define NICTOOL_ETS_BANDWIDTH_CFG_FLAG		0x4
#define NICTOOL_ETS_SCHEDULE_CFG_FLAG		0x8

#define NICTOOL_ETS_MAC_TC_NUM			8

#define NICTOOL_PFC_EN_CFG_FLAG			0x1
#define NICTOOL_PFC_PRIEN_CFG_FLAG		0x2
#define NICTOOL_PFC_TIME_CFG_FLAG		0x4
#define NICTOOL_PFC_GAP_CFG_FLAG		0x8

#define NICTOOL_PFC_MAC_PRI			8

int hns3_test_dcb_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size);
int hns3_test_dcb_ets_cfg(struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size);
int hns3_test_dcb_pfc_cfg(struct hns3_nic_priv *net_priv,
			  void *buf_in, u32 in_size,
			  void *buf_out, u32 out_size);
#endif
