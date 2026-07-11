/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2023 - 2024 ZTE Corporation */

#ifndef ZXDH_TOOLS_NETLINK_H_
#define ZXDH_TOOLS_NETLINK_H_
#define NLA_DATA(na) ((void *)((char *)(na) + NLA_HDRLEN))
#define ZXDH_TOOLS_NETLINK_NAME "tools_family"

enum EVENT_OP_CODE_TO_H {
	EVENT_OP_CODE_DEV_PCIEID_TO_H = 0,
	EVENT_OP_CODE_LOG_GET_TO_H = 1,
	EVENT_OP_CODE_DIAG_TO_H = 2,
	EVENT_OP_CODE_STAT_TO_H = 3,
	EVENT_OP_CODE_REGSDUMP_TO_H = 4,
	EVENT_OP_CODE_REGSMEM_TO_H = 5,
	EVENT_OP_CODE_SN_MAC_SEND_TO_H = 6,
	EVENT_OP_CODE_FWUPDATE_TO_H = 7,
	EVENT_OP_CODE_DINGHAI_RESET_TO_H = 8,
	EVENT_OP_CODE_FPUT_TO_H = 10,
	EVENT_OP_CODE_LOG_GET_FINISH_TO_H = 11,
	EVENT_OP_CODE_FPUT_FLASH_TO_H = 14,
	EVENT_OP_CODE_NUM_TO_H = 100,
};

enum {
	ZXDH_TOOLS_A_UNSPEC,
	ZXDH_TOOLS_A_MSG,
	__ZXDH_TOOLS_A_MAX,
};
#define ZXDH_TOOLS_A_MAX (__ZXDH_TOOLS_A_MAX - 1)

enum {
	ZXDH_TOOLS_C_UNSPEC,
	ZXDH_TOOLS_C_ECHO,
	__ZXDH_TOOLS_C_ECHO,
};
#define ZXDH_TOOLS_C_MAX (__ZXDH_TOOLS_C_MAX - 1)

enum event_op_code {
	FWUPDATE = 27,
};

struct zxdh_tools_recv_msg {
	enum event_op_code op_code;
	u8 status;
};

s32 zxdh_tools_sendto_user_netlink(void *pay_load, u16 len, void *reps_buffer, u16 *reps_len,
				   void *dev);
int zxdh_tools_netlink_register(void);
void zxdh_tools_netlink_unregister(void);

#endif /* ZXDH_TOOLS_NETLINK_H_  */
