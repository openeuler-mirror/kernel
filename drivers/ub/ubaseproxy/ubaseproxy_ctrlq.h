/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_CTRLQ_H__
#define __UBASEPROXY_CTRLQ_H__

#include "ubaseproxy_dev.h"

struct ubaseproxy_ctrlq_query_sl_resp {
	__le16 um_sl_bitmap;
	__le16 rc_max_cnt;
	__le16 tp_sl_bitmap;
	__le16 ctp_sl_bitmap;
	u8 rsv1[12];
};

int ubaseproxy_ctrlq_handle_query_sl_resp(struct auxiliary_device *adev,
					  void *data, u16 len);

#endif /* __UBASEPROXY_CTRLQ_H__ */
