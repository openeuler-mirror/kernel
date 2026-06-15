/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __VLAN_H__
#define __VLAN_H__

#include <net/flow_offload.h>
#include "common/tc_priv.h"

struct pedit_headers_action;

int xsc_tc_act_vlan_add_push_action(struct xsc_adapter *priv,
				    struct xsc_flow_attr *attr,
				    struct net_device **out_dev,
				    struct netlink_ext_ack *extack);

int xsc_tc_act_vlan_add_pop_action(struct xsc_adapter *priv,
				   struct xsc_flow_attr *attr,
				   struct netlink_ext_ack *extack);

int xsc_tc_act_vlan_add_rewrite_action(struct xsc_adapter *priv, int namespace,
				       const struct flow_action_entry *act,
				       struct xsc_tc_flow_parse_attr *parse_attr,
				       u32 *action, struct netlink_ext_ack *extack);

#endif /* __VLAN_H__ */
