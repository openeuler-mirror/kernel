/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright(c) 2021 Ramaxel Memory Technology, Ltd */

#ifndef SPHW_MGMT_MSG_BASE_H
#define SPHW_MGMT_MSG_BASE_H

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
