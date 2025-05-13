/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_ETH_CTRL_H
#define XSC_ETH_CTRL_H

void xsc_eth_ctrl_fini(void);
int xsc_eth_ctrl_init(void);
void xsc_handle_netlink_cmd(struct xsc_core_device *xdev, void *in, void *out);

#endif /* XSC_RXTX_H */
