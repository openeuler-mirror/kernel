/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef __UBASE_PROXY_H__
#define __UBASE_PROXY_H__

#include "ubase_dev.h"

struct ubase_isolated_notify_cmd {
	__le16	bus_ue_id;
	u8	status;
	u8	resv[21];
};

struct ubase_query_ue_isolated_state_cmd {
	__le16 first_bus_ue_id;
	u8 rsv[2];
	__le32 bitmap[5];
};

int ubase_ue_req_ctx_buf(struct ubase_dev *udev);
int ubase_handle_ue_ctx_va_resp(void *dev, void *data, u32 len);
int ubase_handle_ue_isolated_notify_event(void *dev, void *data, u32 len);
int ubase_init_ue_isolated_state(struct ubase_dev *udev);
int ubase_update_ue_isolated_state(struct ubase_dev *udev);

#endif /* __UBASE_PROXY_H__ */
