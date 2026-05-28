// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "act.h"

#ifdef HAVE_FLOW_ACTION_PTYPE
static int tc_act_parse_ptype(struct xsc_tc_act_parse_state *parse_state,
			      const struct flow_action_entry *act,
			      struct xsc_adapter *priv,
			      struct xsc_flow_attr *attr)
{
	struct netlink_ext_ack *extack = parse_state->extack;

	if (act->ptype != PACKET_HOST) {
		NL_SET_ERR_MSG_MOD(extack, "skbedit ptype is only supported with type host");
		netdev_err(priv->netdev, "skbedit ptype is only supported with type host\n");
		return -EOPNOTSUPP;
	}

	parse_state->ptype_host = true;
	return 0;
}

struct xsc_tc_act xsc_tc_act_ptype = {
	.parse_action = tc_act_parse_ptype,
};
#endif
