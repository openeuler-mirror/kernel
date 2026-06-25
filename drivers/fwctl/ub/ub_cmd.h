/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2025-2025. All rights reserved.
 */

#ifndef __UB_CMD_H__
#define __UB_CMD_H__

#include "ub_common.h"

struct ubctl_func_dispatch *ubctl_get_query_func(struct ubctl_dev *ucdev,
						 u32 rpc_cmd);
int ubctl_port_link_status_init(struct auxiliary_device *adev, struct ubctl_dev *ucdev);
void ubctl_port_link_status_uninit(struct auxiliary_device *adev);
int ubctl_handle_link_status_event(void *dev, void *data, u32 len);

#endif
