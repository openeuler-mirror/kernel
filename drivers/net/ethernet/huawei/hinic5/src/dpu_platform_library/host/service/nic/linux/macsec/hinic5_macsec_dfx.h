/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_dfx.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Device entities storage
 */

#ifndef HINIC5_MACSEC_DFX_H
#define HINIC5_MACSEC_DFX_H

#include <linux/netdevice.h>

#include "hinic5_nic_dev.h"

#include "macsec_mpu_cmd_defs.h"
#include "macsec_pub_cmd.h"

#define HIMACSEC_DRV_VER "100.0.1.100"

#define macsec_err(dev, format, ...) dev_err(dev, "[MACsec]" format, ##__VA_ARGS__)
#define macsec_warning(dev, format, ...) dev_warn(dev, "[MACsec]" format, ##__VA_ARGS__)
#define macsec_notice(dev, format, ...) dev_notice(dev, "[MACsec]" format, ##__VA_ARGS__)
#define macsec_info(dev, format, ...) dev_info(dev, "[MACsec]" format, ##__VA_ARGS__)

void himacsec_dfx_convert_key_length(u32 *key_length, u32 chip_key_len_val);
void himacsec_dfx_show_sa(struct hinic5_nic_dev *nic_dev,
			  macsec_sa_info_s *sa_info, crypt_direction_e direct);
void himacsec_dfx_show_sc(struct hinic5_nic_dev *nic_dev,
			  macsec_sc_info_s *sc_info, crypt_direction_e direct);

#endif
