/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPNIC_NIC_DBG_H
#define SPNIC_NIC_DBG_H

#include "spnic_nic_io.h"

int spnic_dbg_get_sq_info(void *hwdev, u16 q_id, struct nic_sq_info *sq_info, u32 msg_size);

int spnic_dbg_get_rq_info(void *hwdev, u16 q_id, struct nic_rq_info *rq_info, u32 msg_size);

int spnic_dbg_get_wqe_info(void *hwdev, u16 q_id, u16 idx, u16 wqebb_cnt,
			   u8 *wqe, u16 *wqe_size, enum spnic_queue_type q_type);

#endif
