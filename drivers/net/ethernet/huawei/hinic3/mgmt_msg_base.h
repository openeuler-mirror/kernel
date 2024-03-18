/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2022. All rights reserved.
 * File Name     : mgmt_msg_base.h
 * Version       : Initial Draft
 * Created       : 2021/6/28
 * Last Modified :
 * Description   : COMM Command interfaces between Driver and MPU
 * Function List :
 */

#ifndef MGMT_MSG_BASE_H
#define MGMT_MSG_BASE_H

#define MGMT_MSG_CMD_OP_SET	1
#define MGMT_MSG_CMD_OP_GET	0

#define MGMT_MSG_CMD_OP_START	1
#define MGMT_MSG_CMD_OP_STOP	0

struct mgmt_msg_head {
	u8 status;
	u8 version;
	u8 rsvd0[6];
};

#endif
