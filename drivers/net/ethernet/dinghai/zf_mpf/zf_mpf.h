/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef __ZXDH_ZF_MPF_H__
#define __ZXDH_ZF_MPF_H__
#include <linux/workqueue.h>
#include <linux/dinghai/driver.h>
#include <linux/dinghai/log.h>
#include "gdma.h"

#define ZXDH_MPF_VENDOR_ID 0x1cf2
#define ZXDH_MPF_DEVICE_ID0 0x8044
#define ZXDH_MPF_DEVICE_ID1 0x806a

#define ZXDH_BAR1_CHAN_OFFSET 0x2000 //0x7801000
#define ZXDH_BAR2_CHAN_OFFSET 0x3000 //0x7802000
#define VERSION_OF_ZF_MPF_OFFSET 0x5438
#define FW_FEATURE_OF_ZF_MPF_OFFSET 0x1004
#define FW_FEATURE_SUPPORT_MASK 0x10000
#define ZF_MPF_COMPAT_ITEM 8

struct dh_en_mpf_dev {
	u16 ep_bdf;
	u16 pcie_id;
	u16 vport;

	u64 pci_ioremap_addr;

	struct work_struct dh_np_sdk_from_risc;
	struct work_struct dh_np_sdk_from_pf;

	struct zf_gdma_dev *gdev;
};

struct fw_compat_version {
	u8 major;
	u8 fw_minor;
	u8 drv_minor;
	u16 patch;
};

struct version_compat_reg {
	u8 version_compat_item;
	u8 major;
	u8 fw_minor;
	u8 drv_minor;
	u16 patch;
	u8 rsv[2];
};

extern int zxdh_bar_chan_sync_msg_send(struct zxdh_pci_bar_msg *in,
				       struct zxdh_msg_recviver_mem *result);
extern int zxdh_bar_chan_msg_recv_register(u8 event_id, zxdh_bar_chan_msg_recv_callback callback);
extern int zxdh_bar_chan_msg_recv_unregister(u8 event_id);
extern int pcie_zte_zf_signal_epc_dev_init(u32 ep_idx);

extern struct devlink_ops dh_mpf_devlink_ops;
extern struct dh_core_devlink_ops dh_mpf_core_devlink_ops;

extern int zxdh_host_reset_driver_init(struct dh_core_dev *core_dev);
extern void zxdh_host_reset_driver_exit(struct dh_core_dev *core_dev);
extern int zxdh_host_fuc_hotplug_driver_init(void);
extern void zxdh_host_fuc_hotplug_driver_exit(void);
extern int zf_reset_finish_flag_init(struct dh_core_dev *dh_dev, unsigned long ep_mpf_paddr);
extern void zf_reset_finish_flag_exit(void);
extern int zxdh_bar_ioctl_msg_mdl_init(struct dh_core_dev *core_dev);
extern void zxdh_bar_ioctl_msg_mdl_exit(struct dh_core_dev *core_dev);
#endif /* __ZXDH_EN_MPF_H__ */
