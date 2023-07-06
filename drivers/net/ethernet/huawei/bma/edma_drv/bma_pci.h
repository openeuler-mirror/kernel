/* SPDX-License-Identifier: GPL-2.0 */
/* Huawei iBMA driver.
 * Copyright (c) 2017, Huawei Technologies Co., Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#ifndef _BMA_PCI_H_
#define _BMA_PCI_H_

#include "bma_devintf.h"
#include "bma_include.h"
#include <linux/netdevice.h>

#define EDMA_SWAP_BASE_OFFSET	0x10000

#define HOSTRTC_REG_BASE	0x2f000000
#define HOSTRTC_REG_SIZE	EDMA_SWAP_BASE_OFFSET

#define EDMA_SWAP_DATA_BASE	0x84810000
#define EDMA_SWAP_DATA_SIZE	65536

#define VETH_SWAP_DATA_BASE	0x84820000
#define VETH_SWAP_DATA_SIZE	0xdf000

#define ATU_VIEWPORT		0x900
#define	ATU_REGION_CTRL1	0x904
#define ATU_REGION_CTRL2	0x908
#define ATU_BASE_LOW		0x90C
#define ATU_BASE_HIGH		0x910
#define ATU_LIMIT		0x914
#define	ATU_TARGET_LOW		0x918
#define ATU_TARGET_HIGH		0x91C
#define REGION_DIR_OUTPUT	(0x0 << 31)
#define REGION_DIR_INPUT	(0x1 << 31)
#define REGION_INDEX_MASK	0x7
#define	REGION_ENABLE		(0x1 << 31)
#define	ATU_CTRL1_DEFAULT	0x0
struct bma_pci_dev_s {
	unsigned long kbox_base_phy_addr;
	void __iomem *kbox_base_addr;
	unsigned long kbox_base_len;

	unsigned long bma_base_phy_addr;
	void __iomem *bma_base_addr;
	unsigned long bma_base_len;

	unsigned long hostrtc_phyaddr;
	void __iomem *hostrtc_viraddr;

	unsigned long edma_swap_phy_addr;
	void __iomem *edma_swap_addr;
	unsigned long edma_swap_len;

	unsigned long veth_swap_phy_addr;
	void __iomem *veth_swap_addr;
	unsigned long veth_swap_len;

	struct pci_dev *pdev;
	struct bma_dev_s *bma_dev;
};

#ifdef DRV_VERSION
#define BMA_VERSION MICRO_TO_STR(DRV_VERSION)
#else
#define BMA_VERSION "0.3.6"
#endif

#ifdef CONFIG_ARM64
#define IOREMAP ioremap_wc
#else
#ifdef ioremap_nocache
#define IOREMAP ioremap_nocache
#else
#define IOREMAP ioremap_wc
#endif
#endif

extern int debug;

#define BMA_LOG(level, fmt, args...) \
	do { \
		if (debug >= (level))\
			netdev_alert(0, "edma: %s, %d, " fmt, \
				__func__, __LINE__, ## args); \
	} while (0)

int edmainfo_show(char *buff);

#endif
