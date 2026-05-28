/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2025 - 2025, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef XSC_HEALTH_H
#define XSC_HEALTH_H

#define XSC_HEALTH_NIC_STATE_OFFSET	0xb00
#define XSC_HEALTH_COUNTER_OFFSET	0xb80

#define	XSC_HEALTH_BUFFER_OFFSET	0xbc0

#define	XSC_HEALTH_POLL_INTERVAL_MS	2000
#define XSC_FW_RESET_MS			60000

#define MAX_MISS			3

#define XSC_MAX_FAILED_RECOVERS_IN_SEQUENCE 3

enum {
	XSC_DROP_HEALTH_WORK,
};

enum {
	XSC_SENSOR_NO_ERR		= 0,
	XSC_SENSOR_COMMON_ERR		= 1,
	XSC_SENSOR_PCI_ERR		= 2,
	XSC_SENSOR_NIC_DISABLED		= 3,
};

enum {
	XSC_NIC_STATE_DISABLED		= 1,
};

enum {
	XSC_HEALTH_SYNDROME_FW_INTERNAL_ERR	= 1,
	XSC_HEALTH_SYNDROME_HIGH_TEMP_ERR	= 2,
	XSC_HEALTH_SYNDROME_HW_FATAL_ERR	= 3,
	XSC_HEALTH_SYNDROME_PCI_ERR		= 4,
};

enum {
	XSC_FW_REPORTER_VF_GRACEFUL_PERIOD	= 30000,
	XSC_FW_REPORTER_PF_GRACEFUL_PERIOD	= 60000,
};

struct xsc_fw_reporter_ctx {
	u8 err_synd;
	int miss_counter;
};

int xsc_pci_not_working(struct xsc_core_device *dev);
u32 xsc_health_check_fatal_sensors(struct xsc_core_device *dev);

#endif
