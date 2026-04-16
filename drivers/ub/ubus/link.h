/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */

#ifndef __LINK_H__
#define __LINK_H__

struct link_msg_payload {
	/* DW0 */
	u32 scna : 24;
	u32 rsv0 : 8;
	/* DW1 */
	u32 port_idx : 16;
	u32 rsv1 : 16;
};

#define UB_LINK_MSG_SIZE 40

enum ub_link_event {
	UB_LINK_UP,
	UB_LINK_DOWN
};

int ublc_link_up_handle(struct ub_port *port, int src);
int ublc_link_down_handle(struct ub_port *port);
void ub_link_msg_handler(struct ub_bus_controller *ubc, void *pkt, u16 len);
void ublc_handle_all_link_down(struct ub_port *port, struct ub_entity *r_uent);

#endif /* __LINK_H__ */
