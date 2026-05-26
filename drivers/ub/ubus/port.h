/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) HiSilicon Technologies Co., Ltd. 2025. All rights reserved.
 */
#ifndef __PORT_H__
#define __PORT_H__

#define for_each_uent_port(p, d) \
	for ((p) = (d)->ports; ((p) - (d)->ports) < (d)->port_nums; (p)++)

enum ub_port_reset_notify_type {
	RESET_PREPARE,
	RESET_DONE
};

struct ub_port;
struct ub_entity;
void ub_port_disconnect(struct ub_port *port);
void ub_port_connect(struct ub_port *port, struct ub_port *r_port);
bool ub_check_and_connect(struct ub_port *port, struct ub_entity *r_uent);
int ub_ports_add(struct ub_entity *uent);
void ub_ports_del(struct ub_entity *uent);
int ub_ports_setup(struct ub_entity *uent);
void ub_ports_unset(struct ub_entity *uent);
void ub_notify_share_port(struct ub_port *port,
			  enum ub_port_event type);
struct ub_share_port_ops *ub_port_event_handler_get(void);

int ub_port_read_byte(struct ub_port *port, u32 pos, u8 *val);
int ub_port_write_dword(struct ub_port *port, u32 pos, u32 val);
bool ub_port_check_link_up(struct ub_port *port);

#endif /* __PORT_H__ */
