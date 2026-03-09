/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2025 HiSilicon Technologies Co., Ltd. All rights reserved.
 *
 */

#ifndef _UB_UBASE_COMM_QOS_H_
#define _UB_UBASE_COMM_QOS_H_

#include <linux/dcbnl.h>
#include <ub/ubus/ubus.h>
#include <ub/ubase/ubase_comm_dev.h>

enum ubase_sl_sched_mode {
	UBASE_SL_SP = IEEE_8021QAZ_TSA_STRICT,
	UBASE_SL_DWRR = IEEE_8021QAZ_TSA_ETS,
};

/**
 * struct ubase_sl_priqos - priority qos
 * @port_bitmap: port bitmap
 * @sl_bitmap: sl bitmap
 * @weight: bandwidth weight
 * @sch_mode: schedule mode
 */
struct ubase_sl_priqos {
	u32 port_bitmap;
	u32 sl_bitmap;
	u8 weight[UBASE_MAX_SL_NUM];
	u8 sch_mode[UBASE_MAX_SL_NUM];
	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

/**
 * struct ubase_initial_qset_qos - ubase initial tm qset configuration
 * @num: tm qset number
 * @qset_id: qset id
 * @qset_weight: qset scheduling weight
 * @rate: qset rate
 * @vl: vl corresponding to qset
 */
struct ubase_initial_qset_qos {
	u8 num;
	u8 qset_id[UBASE_MAX_VL_NUM];
	u8 qset_weight[UBASE_MAX_VL_NUM];
	u32 rate[UBASE_MAX_VL_NUM];
	u8 vl[UBASE_MAX_VL_NUM];

	KABI_RESERVE(1)
	KABI_RESERVE(2)
	KABI_RESERVE(3)
	KABI_RESERVE(4)
};

int ubase_set_priqos_info(struct device *dev, struct ubase_sl_priqos *sl_priqos);
int ubase_get_priqos_info(struct device *dev, struct ubase_sl_priqos *sl_priqos);

int ubase_check_qos_sch_param(struct auxiliary_device *adev, u16 vl_bitmap,
			      u8 *vl_bw, u8 *vl_tsa, bool is_ets);
int ubase_config_tm_vl_sch(struct auxiliary_device *adev, u16 vl_bitmap,
			   u8 *vl_bw, u8 *vl_tsa);
void ubase_update_udma_dscp_vl(struct auxiliary_device *adev, u8 *dscp_vl,
			       u8 dscp_num);
int ubase_config_tm_vl_rate_limit(struct auxiliary_device *adev, u16 vl_bitmap,
				  u32 *vl_maxrate);
int ubase_restore_initial_qset_qos(struct auxiliary_device *adev);
struct ubase_initial_qset_qos *
ubase_get_initial_qset_qos(struct auxiliary_device *adev);

int ubase_set_dscp_tc_map(struct auxiliary_device *adev, u64 dscp_bitmap,
			  u8 *vl);
#endif /* _UBASE_COMM_QOS_H_ */
