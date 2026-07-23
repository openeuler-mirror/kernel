/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __PCIE_ZTE_ZF_JSON_H
#define __PCIE_ZTE_ZF_JSON_H

#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sysfs.h>
#include <linux/kobject.h>
#include <linux/err.h>
#include <linux/namei.h>
#include <linux/dcache.h>
#include <linux/fs.h>
#include <linux/dinghai/dh_cmd.h>

#include "../zf_mpf.h"
#include "pcie-zte-zf-epc.h"

#ifdef _cplusplus
extern "C" {
#endif

#define ZXDH_SYSFS_DIR "zxdh_sysfs"
#define ZXDH_SYSFS_PATH "/sys/zxdh_sysfs"
#define RECV_BUFFER_SIZE 30
#define BAR_MSG_HEADER_SIZE 4

struct dpu_pf_cfg {
	u8 ep_id;
	u8 pf_id;
	u8 pf_enable;
	u8 dev_type;
	u32 vendor_id;
	u32 device_id;
	u32 max_vf;
};
static int pcie_zte_zf_get_dev_cfg(struct dh_core_dev *core_dev);

extern int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in,
				       struct zxdh_msg_recviver_mem *result);

#endif
