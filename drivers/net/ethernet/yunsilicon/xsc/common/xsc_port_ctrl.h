/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_PORT_CTRL_H
#define XSC_PORT_CTRL_H

typedef void (*port_ctrl_cb)(struct xsc_core_device *xdev, unsigned int cmd,
			struct xsc_ioctl_hdr __user *user_hdr, void *data);

void xsc_port_ctrl_remove(struct xsc_core_device *dev);
int xsc_port_ctrl_probe(struct xsc_core_device *dev);
int xsc_port_ctrl_cb_reg(const char *name, port_ctrl_cb cb, void *data);
void xsc_port_ctrl_cb_dereg(const char *name);

void xsc_port_ctrl_fini(void);
int xsc_port_ctrl_init(void);

#endif

