/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C), 2026-2026, Huawei Tech. Co., Ltd.
 * File Name     : nic_mpu_cmd_structs_extend.h
 * Version       : Initial Draft
 * Created       : 2026/5/20
 * Last Modified : 2026/5/20
 * Description   :
 */

#ifndef HINIC5_NIC_CMD_STRUCTS_EXTEND_H
#define HINIC5_NIC_CMD_STRUCTS_EXTEND_H

#if defined(__LINUX__) || defined(__VMWARE__)
#include <linux/types.h>
#endif

#include "mpu_cmd_base_defs.h"
#include "nic_mpu_cmd_structs.h"

#ifndef FUNC_MAX_CLEAR_QP_NUM
#define FUNC_MAX_CLEAR_QP_NUM 256
/**
 * @brief Define a structure for clearing qp resources by queue level
 * @details qp_num indicates the number of queues to clear, qp indicates the local_id of the queues to clear under func
 */
struct hinic5_cmd_clear_assign_qp_res {
	struct hinic5_mgmt_msg_head msg_head;

	u16 func_id;
	u16 qp_num;
	u32 rsvd[4];
	u16 qp[FUNC_MAX_CLEAR_QP_NUM];
};
#endif
#endif /* HINIC5_NIC_CMD_STRUCTS_EXTEND_H */