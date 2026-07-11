/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_EN_MPF_H__
#define __ZXDH_EN_MPF_H__

#include <linux/workqueue.h>
#include <linux/dinghai/driver.h>

#define ZXDH_MPF_VENDOR_ID 0x1111
#define ZXDH_MPF_DEVICE_ID 0x1041

#define ZXDH_BAR1_CHAN_OFFSET 0x2000 //0x7801000
#define ZXDH_BAR2_CHAN_OFFSET 0x3000 //0x7802000

struct dh_en_mpf_dev {
	u16 ep_bdf;
	u16 pcie_id;
	u16 vport;

	u64 pci_ioremap_addr;

	struct work_struct dh_np_sdk_from_risc;
	struct work_struct dh_np_sdk_from_pf;
};

#endif /* __ZXDH_EN_MPF_H__ */
