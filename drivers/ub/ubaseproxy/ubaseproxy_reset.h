/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2026 HiSilicon Technologies Co., Ltd. All rights reserved.
 */

#ifndef __UBASEPROXY_RESET_H__
#define __UBASEPROXY_RESET_H__

#include <ub/ubase/ubase_comm_dev.h>

struct ubaseproxy_ue_reset_notify_cmd {
	__le16	bus_ue_id;
	__le16	mbx_ue_id;
	u8	resv[20];
};

int ubaseproxy_handle_ue_reset_notify(void *dev, void *data, u32 len);
int ubaseproxy_reset_handler(struct auxiliary_device *adev,
			     enum ubase_reset_stage stage);

#endif /* __UBASEPROXY_RESET_H__ */
