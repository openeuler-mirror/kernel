/* SPDX-License-Identifier: GPL-2.0 */
/**
 * Copyright (C), 2020, sxe2rdma Technologies Co., Ltd.
 *
 * @file: sxe2_ioctl.h
 * @author: sxe2rdma
 * @date: 2025.02.16
 * @brief:
 * @note:
 */

#ifndef __SXE2_IOCTL_H__
#define __SXE2_IOCTL_H__

#include "sxe2_internal_ver.h"

struct sxe2_ioctl_sync_cmd {
	u32 ver;
	u32 resv;
	u64 trace_id;
	u32 timeout;
	u8 resv1[4];
	void *in_data;
	u32 in_len;
	u8 resv2[4];
	void *out_data;
	u32 out_len;
	u8 resv3[4];
};

#define SXE2_CMD_IOCTL_SYNC_CMD        _IOWR('M', 1, struct sxe2_ioctl_sync_cmd)
#define SXE2_CMD_IOCTL_SYNC_DRV_CMD    _IOWR('M', 2, struct sxe2_ioctl_sync_cmd)

#endif
