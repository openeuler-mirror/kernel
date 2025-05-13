/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef TUNNEL_CMD_H
#define TUNNEL_CMD_H

#include "common/xsc_core.h"

void xsc_tunnel_cmd_init(struct xsc_core_device *xdev);
void xsc_tunnel_cmd_recv_resp(struct xsc_core_device *xdev);
int xsc_tunnel_cmd_exec(struct xsc_core_device *xdev, void *in, int inlen, void *out, int outlen,
			struct xsc_ioctl_tunnel_hdr *hdr);
int xsc_tunnel_cmd_recv_req(struct xsc_core_device *xdev);

#endif
