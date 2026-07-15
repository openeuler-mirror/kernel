/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_api.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : MACsec api header file
 */

#ifndef HINIC5_MACSEC_API_H
#define HINIC5_MACSEC_API_H

#include <linux/types.h>
#include "hinic5_nic_dev.h"

/* MACsec initialization */
int macsec_init_offload(struct hinic5_nic_dev *nic_dev);
void macsec_cleanup_offload(struct hinic5_nic_dev *nic_dev);

/* MACsec ioctl interface */
int macsec_cmd_list(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		    u32 in_size, void *buf_out, u32 *out_size);
int macsec_cmd_mib(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size);
int macsec_cmd_add(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size);
int macsec_cmd_del(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size);
int macsec_cmd_set(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		   u32 in_size, void *buf_out, u32 *out_size);
int macsec_cmd_flush(struct hinic5_nic_dev *nic_dev, const void *buf_in,
		     u32 in_size, void *buf_out, u32 *out_size);

#endif  // HINIC5_MACSEC_API_H
