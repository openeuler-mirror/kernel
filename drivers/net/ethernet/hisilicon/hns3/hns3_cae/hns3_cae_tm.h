/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2016-2019 Hisilicon Limited. */

#ifndef __HNS3_CAE_TM_H__
#define __HNS3_CAE_TM_H__

#include "hns3_enet.h"

#define MAX_QUEUE_NUM				16
#define MAX_PG_NUM				4
#define MAX_TC_NUM				8
#define HNS3_TEST_QS_ID_MSK			(BIT(10) - 1)
#define HCLGE_OPC_TM_PORT_SCH_MODE_CFG		0x0811

#define HNS3_TM_QSET_MAPPING_FLAG		0x01
#define HNS3_TM_QSET_MODE_CFG_FLAG		0x02
#define HNS3_TM_QSET_WEIGHT_CFG_FLAG		0x04
#define HNS3_TM_QSET_BP_CFG_FLAG		0x08

#define HNS3_TM_PRI_MAPPING_FLAG		0x01
#define HNS3_TM_PRI_MODE_CFG_FLAG		0x02
#define HNS3_TM_PRI_WEIGHT_CFG_FLAG		0x04
#define HNS3_TM_PRI_CSHAP_CFG_FLAG		0x08
#define HNS3_TM_PRI_PSHAP_CFG_FLAG		0x10

#define HNS3_TM_PG_MODE_CFG_FLAG		0x01
#define HNS3_TM_PG_WEIGHT_CFG_FLAG		0x02
#define HNS3_TM_PG_CSHAP_CFG_FLAG		0x04
#define HNS3_TM_PG_PSHAP_CFG_FLAG		0x08

#define HNS3_TM_PORT_MODE_CFG_FLAG		0x01
#define HNS3_TM_PORT_WEIGHT_CFG_FLAG		0x02
#define HNS3_TM_PORT_PSHAP_CFG_FLAG		0x04

#define HNS3_TM_ETS_PSHAP_CFG_FLAG		0x01
#define HNS3_TM_ETS_TC_CFG_FLAG			0x02

struct nictool_ets_tc_weight_cmd {
	u8 tc_weight[MAX_TC_NUM];
	u8 weight_offset;
	u8 rsvd[15];
};

struct nictool_queue_cfg_info {
	int is_read;
	u16 queue_id;
	u16 qs;
};

struct nictool_qs_cfg_info {
	int is_read;
	u16 qs_id;
	u8 pri;
	u8 mode;
	u8 weight;
	u8 tc;
	u8 flag;
};

struct nictool_pri_cfg_info {
	int is_read;
	u16 pri_id;
	u8 pg;
	u32 c_shaping;
	u32 p_shaping;
	u8 mode;
	u8 weight;
	u8 flag;
};

struct nictool_pg_cfg_info {
	int is_read;
	u16 pg_id;
	u32 c_shaping;
	u32 p_shaping;
	u8 mode;
	u8 weight;
	u8 flag;
};

struct nictool_port_cfg_info {
	int is_read;
	u16 port_id;
	u32 mode;
	u32 shaping;
	u8 weight;
	u8 flag;
};

struct nictool_ets_cfg_info {
	int is_read;
	u16 tc_id;
	u8 weight;
	u32 shaping;
	u8 mac_id;
	u8 flag;
};

int hns3_test_queue_cfg(struct hns3_nic_priv *net_priv,
			void *buf_in, u32 in_size,
			void *buf_out, u32 out_size);
int hns3_test_qs_cfg(struct hns3_nic_priv *net_priv,
		     void *buf_in, u32 in_size, void *buf_out, u32 out_size);
int hns3_test_pri_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size);
int hns3_test_pg_cfg(struct hns3_nic_priv *net_priv, void *buf_in, u32 in_size,
		     void *buf_out, u32 out_size);
int hns3_test_port_cfg(struct hns3_nic_priv *net_priv,
		       void *buf_in, u32 in_size,
		       void *buf_out, u32 out_size);
int hns3_test_ets_cfg(struct hns3_nic_priv *net_priv,
		      void *buf_in, u32 in_size, void *buf_out, u32 out_size);

#endif
