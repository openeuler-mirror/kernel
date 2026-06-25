/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_common.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : common define
 */

#ifndef HINIC5_MACSEC_COMMON_H
#define HINIC5_MACSEC_COMMON_H

#include <linux/types.h>

#include "macsec_mpu_cmd.h"
#include "macsec_mpu_cmd_defs.h"
#include "macsec_pub_cmd.h"
#include "hinic5_nic_dev.h"
#include "hinic5_macsec_dev.h"

#define PORT_MSK_IN_SCI 0x00FF /* Generalized port, currently represents sc_index */
#define MACSEC_SC_STATUS_VALID(status) \
	((((status) == SC_STATUS_MAX) || ((status) == SC_STATUS_NONE)) ? 0 : 1)
#define MACSEC_SA_STATUS_VALID(status) \
	((((status) >= SA_STATUS_EXPIRED) || ((status) == SA_STATUS_NONE)) ? 0 : 1)
#define HIMACSEC_CONFIDENTIALITY_OFFSET_0 0
#define HIMACSEC_CONFIDENTIALITY_OFFSET_30 1
#define HIMACSEC_CONFIDENTIALITY_OFFSET_50 2

typedef enum {
	HIMACSEC_SC_MODE_TWO_SA,
	HIMACSEC_SC_MODE_FOUR_SA,
	HIMACSEC_SC_MODE_MAX
} himacsec_sc_mode_e;

/* Used to determine if MACsec global switch is on, which affects NIC service if enabled */
#define MACSEC_GLOBAL_SWITCH_IS_DISABLE 0
#define MACSEC_GLOBAL_SWITCH_IS_ENABLE 1

/* MACsec offload adapt */
void himacsec_offload_init(struct hinic5_nic_dev *nic_dev);
void himacsec_offload_deinit(struct hinic5_nic_dev *nic_dev);

/* service function */
int himacsec_create_sa(struct hinic5_nic_dev *nic_dev, macsec_sa_info_s *sa,
		       crypt_direction_e direct);
int himacsec_destroy_sa(struct hinic5_nic_dev *nic_dev, u64 sci, u8 assoc_num,
			crypt_direction_e direct);
int himacsec_create_sc(struct hinic5_nic_dev *nic_dev,
		       macsec_sc_info_s *sc_info, crypt_direction_e direct);
int himacsec_destroy_sc(struct hinic5_nic_dev *nic_dev, u64 sci, crypt_direction_e direct);
int himacsec_set_sc(struct hinic5_nic_dev *nic_dev, macsec_sc_info_s *sc_info,
		    crypt_direction_e direct);
struct himacsec_sc *himacsec_get_valid_dev_sc(struct hinic5_nic_dev *nic_dev,
					      u64 sci, crypt_direction_e direct);
struct himacsec_sa *himacsec_get_valid_dev_sa(struct hinic5_nic_dev *nic_dev,
					      u64 sci, u8 an, crypt_direction_e direct);
struct himacsec_sc *get_g_macsec_port_res(u32 mode, u32 port_id);
struct himacsec_sc *himacsec_get_dev_sc(struct hinic5_nic_dev *nic_dev, crypt_direction_e direct);

/* mailbox msg function */
int himacsec_cmd_exec_get_spec(void *hwdev, struct himacsec_spec *spec);
int himacsec_cmd_exec_macsec_enable(struct hinic5_lld_dev *lld_dev,
				    macsec_mbox_service_op_cmd_e op_code, u8 *macsec_flag);
int himacsec_cmd_exec_sc_op(struct hinic5_lld_dev *lld_dev,
			    macsec_sc_info_s *sc_info, macsec_mbox_sc_op_cmd_e opcode);
int himacsec_cmd_exec_sa_op(struct hinic5_lld_dev *lld_dev,
			    macsec_sa_info_s *sa_info, macsec_mbox_sa_op_cmd_e opcode);
int himacsec_cmd_exec_mib_port(struct hinic5_lld_dev *lld_dev,
			       struct himacsec_cmd_mib_out *cmd_out);
int himacsec_cmd_exec_mib_sc(struct hinic5_lld_dev *lld_dev,
			     struct himacsec_cmd_mib_out *out_buf, u64 sci);
int himacsec_cmd_exec_get_feature_nego(struct hinic5_lld_dev *lld_dev,
				       u64 *feature_bitmap, u32 feature_size);
int himacsec_cmd_exec_flush(struct hinic5_lld_dev *lld_dev, tag_macsec_flush_cmd_s *flush_info);

#endif
