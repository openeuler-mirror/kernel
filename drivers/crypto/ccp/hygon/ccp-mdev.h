/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HYGON Cryptographic Coprocessor (CCP) crypto driver for Mediated device
 *
 * Copyright (C) 2022 Hygon Info Technologies Ltd.
 *
 */

#ifndef __CCP_MDEV_H__
#define __CCP_MDEV_H__

#include <linux/device.h>
#include <linux/pci.h>
#include <linux/miscdevice.h>
#include <linux/kfifo.h>
#include <linux/eventfd.h>
#include <linux/ccp.h>

#define MCCP_INSTANCE_MAX		1024
#define MCCP_DEV_QUEUE			5

enum _CCP_DEV_USED_MODE {
	_KERNEL_SPACE_USED,
	_USER_SPACE_USED,
};

struct hygon_ectx_list {
	DECLARE_KFIFO(ectx_fifo, struct eventfd_ctx *, MCCP_INSTANCE_MAX);
};

struct hygon_ccp_dev_wrapper {
	struct list_head entry;
	struct hygon_ectx_list ectx_q[MCCP_DEV_QUEUE];
	rwlock_t q_lock;
	struct ccp_device *cdev;
	struct pci_dev *pdev;
	unsigned int used_mode;
	unsigned int del_flag; /* 0:ccp in ccp_units 1:ccp not in ccp_units */
};

int ccp_dev_wrapper_list_empty(void);
struct hygon_ccp_dev_wrapper *hygon_ccp_dev_wrapper_get(struct ccp_device *ccp);
int ccp_dev_wrapper_alloc(struct pci_dev *pdev);
void ccp_dev_wrapper_free(struct pci_dev *pdev);
int ccp_mdev_pci_probe(struct pci_dev *pdev);
void ccp_mdev_pci_remove(struct pci_dev *pdev);
int ccp_mdev_init(void);
void ccp_mdev_exit(void);

#endif /* __CCP_MDEV_H__ */
