/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __POOL_H__
#define __POOL_H__

#include "msg.h"

struct entity_base_info {
	/* DW0 */
	u32 entity_idx : 16;
	u32 upi : 15;
	u32 rsvd0 : 1;
	/* DW1~DW4 */
	u32 eid[4];
	/* DW5~DW8 */
	u32 guid[UB_GUID_DW_NUM];
	/* DW9 */
	u32 cna : 24;
	u32 rsvd2 : 8;
	/* DW10~DW13 */
	u32 ueid[4];
};

struct entity_rs_info {
	u32 ss;
	u32 sa_l;
	u32 sa_h;
};

struct entity_reg_msg_pld {
	/* DW0~DW13 */
	struct entity_base_info base;
	/* DW14~DW22 */
	struct entity_rs_info ers[MAX_UB_RES_NUM];
};
#define ENTITY_BASE_PLD_SIZE 56
#define ENTITY_RS_PLD_SIZE 36
#define ENTITY_REG_PLD_SIZE (ENTITY_BASE_PLD_SIZE + ENTITY_RS_PLD_SIZE)

struct entity_rls_msg_pld {
	/* DW0~DW3 */
	u32 eid[4];
	/* DW4 */
	u32 reason : 8;
	u32 rsvd1 : 24;
};
#define ENTITY_RLS_PLD_SIZE 20

struct port_reset_notify_pld {
	u32 type : 1;
	u32 rsvd0 : 15;
	u32 port_index : 16;
};
#define PORT_RESET_NOTIFY_PLD_SIZE 4
struct msg_pkt_header;
bool ub_rsp_msg_init(struct msg_pkt_header *header, u8 status, u32 plen);
void ub_pool_rx_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len);

#endif /* __POOL_H__ */
