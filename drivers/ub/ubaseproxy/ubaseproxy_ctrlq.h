/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_CTRLQ_H__
#define __UBASEPROXY_CTRLQ_H__

#include "ubaseproxy_dev.h"

#define UBASEPROXY_CTRLQ_SEID_NUM	64
#define UBASEPROXY_CTRLQ_SEID_CMD	GENMASK(3, 0)

enum ubaseproxy_ctrlq_seid_event {
	UBASEPROXY_CTRLQ_ADD_SEID,
	UBASEPROXY_CTRLQ_DEL_SEID,
};

enum ubaseproxy_ctrlq_opc_type_seid {
	UBASEPROXY_CTRLQ_GET_SEID_INFO		= 0x1,
	UBASEPROXY_CTRLQ_UPDATE_SEID_INFO	= 0x2,
};

struct ubaseproxy_seid_info {
	__le32 seid_idx;
	__le32 rsv[4];
	__le32 upi;
};

struct ubaseproxy_ctrlq_query_seid_info {
	u8 seid_num;
	u8 rsv[3];
	struct ubaseproxy_seid_info seids[UBASEPROXY_CTRLQ_SEID_NUM];
};

struct ubaseproxy_ctrlq_update_seid_info {
	struct ubaseproxy_seid_info seid_info;
	__le32 seid_operation;
};

struct ubaseproxy_ctrlq_query_sl_resp {
	__le16 um_sl_bitmap;
	__le16 rc_max_cnt;
	__le16 tp_sl_bitmap;
	__le16 ctp_sl_bitmap;
	u8 rsv1[12];
};

int ubaseproxy_ctrlq_handle_query_sl_resp(struct auxiliary_device *adev,
					  void *data, u16 len);
int ubaseproxy_ctrlq_handle_query_eid_resp(struct auxiliary_device *adev,
					   void *data, u16 len);
int ubaseproxy_ctrlq_handle_updata_eid_resp(struct auxiliary_device *adev,
					    void *data, u16 len);

#endif /* __UBASEPROXY_CTRLQ_H__ */
