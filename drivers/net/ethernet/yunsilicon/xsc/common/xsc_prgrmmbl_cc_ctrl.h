/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_PRGRMMBL_CC_CTRL_H
#define XSC_PRGRMMBL_CC_CTRL_H

typedef int (*port_prgrmmbl_cc_ctrl_cb)(struct xsc_bdf_file *file, unsigned int cmd,
			     unsigned long args, void *data);
struct class;

bool xsc_prgrmmble_cc_ctrl_is_supported(struct xsc_core_device *dev);
int xsc_prgrmmbl_cc_ctrl_cb_init(void);
void xsc_prgrmmbl_cc_ctrl_cb_fini(void);
int xsc_prgrmmbl_cc_ctrl_dev_del(struct xsc_core_device *dev,
				 struct class *port_ctrl_class, int *dev_id);
int xsc_prgrmmbl_cc_ctrl_dev_add(struct xsc_core_device *dev,
				 struct class *port_ctrl_class, dev_t dev_id);

int xsc_prgrmmbl_cc_ctrl_cb_reg(const char *name, port_prgrmmbl_cc_ctrl_cb cb, void *data);
void xsc_prgrmmbl_cc_ctrl_cb_dereg(const char *name);
#endif
