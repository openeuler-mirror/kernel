/* SPDX-License-Identifier: GPL-2.0+ */
/* Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved. */

#ifndef __CDMA_TP_H__
#define __CDMA_TP_H__

#include "cdma_types.h"

#define CDMA_CTRLQ_FLAG_ON 1
#define CDMA_CTRLQ_FLAG_OFF 0
#define CDMA_TPN_MASK 0xffffff
#define CDMA_EID_DW_SIZE 4

struct cdma_tp {
	struct cdma_dev *dev;
	struct cdma_base_tp base;
	refcount_t refcount;
	struct completion ae_comp;
};

enum cdma_tp_ctrlq_cmd {
	CDMA_CTRLQ_CREATE_CTP = 0x01,
	CDMA_CTRLQ_DELETE_CTP = 0x02
};

enum cdma_tp_route_type {
	CDMA_ROUTE_TYPE_IPV4,
	CDMA_ROUTE_TYPE_IPV6,
	CDMA_ROUTE_TYPE_CNA,
	CDMA_ROUTE_TYPE_MAX
};

enum cdma_tp_trans_type {
	CDMA_TRANS_TYPE_URMA_TP,
	CDMA_TRANS_TYPE_URMA_CTP,
	CDMA_TRANS_TYPE_UMS_TP,
	CDMA_TRANS_TYPE_CDMA_CTP,
	CDMA_TRANS_TYPE_MAX
};

struct cdma_ctrlq_tp_create_cfg {
	u32 seid_flag; /* 0: 128bits eid, 1: 20bits eid */
	u32 seid[CDMA_EID_DW_SIZE];
	u32 scna;
	u32 deid_flag;
	u32 deid[CDMA_EID_DW_SIZE];
	u32 dcna;
	u32 route_type : 4; /* 0-IPv4, 1-IPv6, 2-CNA */
	u32 trans_type : 4;
	u32 rsv : 24;
};

struct cdma_ctrlq_tp_ret {
	int ret;
};

struct cdma_ctrlq_tp_delete_cfg {
	u32 seid_flag;
	u32 seid[CDMA_EID_DW_SIZE];
	u32 scna;
	u32 deid_flag;
	u32 deid[CDMA_EID_DW_SIZE];
	u32 dcna;
	u32 route_type : 4; /* 0-IPv4, 1-IPv6, 2-CNA */
	u32 trans_type : 4;
	u32 rsv : 24;
	u32 tpn;
};

struct cdma_base_tp *cdma_create_ctp(struct cdma_dev *cdev,
				     struct cdma_tp_cfg *cfg);

void cdma_delete_ctp(struct cdma_dev *cdev, u32 tp_id, bool invalid);

void cdma_destroy_ctp_imm(struct cdma_dev *cdev, u32 tp_id);

#endif /* __CDMA_TP_H__ */
