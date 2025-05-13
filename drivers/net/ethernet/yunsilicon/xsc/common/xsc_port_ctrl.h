/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_PORT_CTRL_H
#define XSC_PORT_CTRL_H

/*mmap msg encode*/
enum {
	XSC_MMAP_MSG_SQDB		= 0,
	XSC_MMAP_MSG_RQDB		= 1,
	XSC_MMAP_MSG_CQDB		= 2,
	XSC_MMAP_MSG_ARM_CQDB	= 3,
};

#define TRY_NEXT_CB	0x1a2b3c4d

typedef int (*port_ctrl_cb)(struct xsc_bdf_file *file, unsigned int cmd,
			struct xsc_ioctl_hdr __user *user_hdr, void *data);

void xsc_port_ctrl_remove(struct xsc_core_device *dev);
int xsc_port_ctrl_probe(struct xsc_core_device *dev);
int xsc_port_ctrl_cb_reg(const char *name, port_ctrl_cb cb, void *data);
void xsc_port_ctrl_cb_dereg(const char *name);

void xsc_port_ctrl_fini(void);
int xsc_port_ctrl_init(void);
struct xsc_core_device *xsc_pci_get_xdev_by_bus_and_slot(int domain, uint32_t bus, uint32_t devfn);
#endif

