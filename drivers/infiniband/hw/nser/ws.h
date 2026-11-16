/* SPDX-License-Identifier: GPL-2.0 or Linux-OpenIB */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */
#ifndef NSER_WS_H
#define NSER_WS_H

#include "osdep.h"

enum nser_ws_node_type {
	WS_NODE_TYPE_PARENT,
	WS_NODE_TYPE_LEAF,
};

enum nser_ws_match_type {
	WS_MATCH_TYPE_VSI,
	WS_MATCH_TYPE_TC,
};

struct nser_ws_node {
	struct list_head siblings;
	struct list_head child_list_head;
	struct nser_ws_node *parent;
	u64 lan_qs_handle; /* opaque handle used by LAN */
	u32 l2_sched_node_id;
	u16 index;
	u16 qs_handle;
	u16 vsi_index;
	u8 traffic_class;
	u8 user_pri;
	u8 rel_bw;
	u8 abstraction_layer; /* used for splitting a TC */
	u8 prio_type;
	bool type_leaf:1;
	bool enable:1;
};

struct nser_sc_vsi;
int nser_ws_add(struct nser_sc_vsi *vsi, u8 user_pri);
void nser_ws_remove(struct nser_sc_vsi *vsi, u8 user_pri);
void nser_ws_reset(struct nser_sc_vsi *vsi);

#endif /* NSER_WS_H */
