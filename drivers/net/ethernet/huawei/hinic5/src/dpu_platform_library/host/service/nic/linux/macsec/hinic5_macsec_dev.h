/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_macsec_dev.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   : Device entities storage
 */

#ifndef HINIC5_MACSEC_DEV_H
#define HINIC5_MACSEC_DEV_H

#include "macsec_mpu_cmd_defs.h"
#include "macsec_pub_cmd.h"
#include "ossl_knl.h"

typedef struct himacsec_spec {
	u8 macsec_support;     /* Whether hardware supports MACsec */
	u8 max_port;           /* Maximum number of ports on the chip */
	u8 max_port_sc;        /* Maximum number of SCs per port */
	u8 max_sa;             /* Maximum number of SA stored per SC */
} himacsec_spec_s;

typedef struct himacsec_stats {
	u64 sa_update_times;
	u64 sa_expire_times;
} himacsec_stats_s;

typedef struct himacsec_mib_stats {
	u32 max_port_size;
	u32 max_port_sc_size;
	macsec_port_mib_info_s *port_mibs;
	macsec_sc_mib_info_s *sc_mibs;
} himacsec_mib_stats_s;

typedef struct macsec_resource {
	struct himacsec_spec spec;
	u64 himacsec_feature[MACSEC_MAX_FEATURE_QWORD];
	u32 num_of_device;
	himacsec_stats_s *stats;  /* Driver internal counter */
	struct notifier_block nb;
	u8 function_port;
	/* macsec sub-device ifindex,
	 * ifindex of offloaded macsec device will be stored in this array
	 */
	u32 offload_child_dev_idx[MACSEC_SC_NUM];
	u32 offload_dev_num;	/* Number of valid elements in offload_child_dev_idx array */
} macsec_resource_s;

struct macsec_port_res {
	struct himacsec_sc enc_sc;  /* Array head pointer */
	struct himacsec_sc dec_sc;
};

struct macsec_extra_param {
	u64 threshold;
	u8 algo_type;
	u8 offset;
	u8 bitmap;
	bool threshold_set;
	bool offset_set;
	u8 rsvd;
};

enum param_bit {
	PARAM_BIT_ENC_SC_ENCODING_SA,
	PARAM_BIT_ENC_SC_PROTECTION_MODE,
	PARAM_BIT_ENC_SC_PROTECT_FRAME_MODE,
	PARAM_BIT_DEC_SC_VALID_FRAM_MODE,
	PARAM_BIT_MAX,
};

#endif
