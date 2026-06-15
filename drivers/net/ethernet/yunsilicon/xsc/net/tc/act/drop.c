// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#include "act.h"
#include "common/tc_priv.h"
#include "common/fs_cmd.h"
#include "common/tc_flow.h"

static int
tc_act_parse_drop(struct xsc_tc_act_parse_state *parse_state,
		  const struct flow_action_entry *act,
		  struct xsc_adapter *priv,
		  struct xsc_flow_attr *attr)
{
	attr->action |= XSC_FLOW_CONTEXT_ACTION_DROP;

	return 0;
}

struct xsc_tc_act xsc_tc_act_drop = {
	.parse_action = tc_act_parse_drop,
	.is_terminating_action = true,
};
