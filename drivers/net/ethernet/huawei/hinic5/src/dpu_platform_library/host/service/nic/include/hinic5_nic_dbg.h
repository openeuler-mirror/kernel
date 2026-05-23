/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : hinic5_nic_dbg.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_DBG_H
#define HINIC5_NIC_DBG_H

#include "nic_pub_cmd.h"
#include "hinic5_nic_io.h"
#include "hinic5_srv_nic.h"

int hinic5_dbg_get_sq_info(void *hwdev, u16 q_id, struct nic_sq_info *sq_info,
			   u32 msg_size);

int hinic5_dbg_get_rq_info(void *hwdev, u16 q_id, struct nic_rq_info *rq_info,
			   u32 msg_size);

int hinic5_dbg_get_wqe_info(void *hwdev, u16 q_id, u16 idx, u16 wqebb_cnt,
			    u8 *wqe, const u16 *wqe_size,
			    enum hinic5_queue_type q_type);

#endif
