// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2021-2021. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License
 * for more details.
 *
 * Description: ubcore kernel module
 * Author: Yanchao Zhao
 * Create: 2024-01-18
 * Note:
 * History: 2024-01-18: create file
 */

#include <net/netlink.h>
#include <net/genetlink.h>
#include <linux/module.h>
#include <linux/list.h>
#include <linux/ctype.h>
#include <linux/version.h>

#include "urma/ubcore_api.h"
#include "ubcore_msg.h"
#include "ubcore_cmd.h"
#include "ubcore_device.h"
#include "ubcore_genl_admin.h"
#include "ubcore_genl_define.h"
#include "ubcore_netlink.h"
#include "ubcore_genl.h"

static const struct nla_policy ubcore_policy[NUM_UBCORE_ATTR] = {
	[UBCORE_ATTR_UNSPEC] = {0},
	[UBCORE_HDR_COMMAND] = { .type = NLA_U32 },
	[UBCORE_HDR_ARGS_LEN] = { .type = NLA_U32 },
	[UBCORE_HDR_ARGS_ADDR] = { .type = NLA_U64 },
	[UBCORE_ATTR_NS_MODE] = { .type = NLA_U8 },
	[UBCORE_ATTR_DEV_NAME] = { .type = NLA_STRING, .len = UBCORE_MAX_DEV_NAME - 1},
	[UBCORE_ATTR_NS_FD] = { .type = NLA_U32 },
	[UBCORE_MSG_SEQ] = { .type = NLA_U32 },
	[UBCORE_MSG_TYPE] = { .type = NLA_U32 },
	[UBCORE_TRANSPORT_TYPE] = { .type = NLA_U32 },
	[UBORE_SRC_ID] = { .len = UBCORE_EID_SIZE},
	[UBORE_DST_ID] = { .len = UBCORE_EID_SIZE},
	[UBCORE_PAYLOAD_LEN] = { .type = NLA_U32 },
	[UBCORE_PAYLOAD_DATA] = { .type = NLA_BINARY },
	[UBCORE_UPDATE_EID_RET] = { .type = NLA_S32 }
};

static const struct genl_ops ubcore_genl_ops[] = {
	{
		.cmd = UBCORE_CMD_SHOW_UTP,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_show_utp_ops
	},
	{
		.cmd = UBCORE_CMD_QUERY_STATS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_query_stats_ops
	},
	{
		.cmd = UBCORE_CMD_QUERY_RES,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.start = ubcore_query_res_start,
		.dumpit = ubcore_query_res_dump,
		.done = ubcore_query_res_done
	},
	{
		.cmd = UBCORE_CMD_ADD_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.start = ubcore_add_eid_start,
		.dumpit = ubcore_add_eid_dump,
		.done = ubcore_add_eid_done
	},
	{
		.cmd = UBCORE_CMD_DEL_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.start = ubcore_delete_eid_start,
		.dumpit = ubcore_delete_eid_dump,
		.done = ubcore_delete_eid_done
	},
	{
		.cmd = UBCORE_CMD_SET_EID_MODE,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_set_eid_mode_ops
	},
	{
		.cmd = UBCORE_CMD_SET_NS_MODE,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_ns_mode_ops
	},
	{
		.cmd = UBCORE_CMD_SET_DEV_NS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_dev_ns_ops
	},
	{
		.cmd = UBCORE_CMD_SET_GENL_PID,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.policy = ubcore_policy,
		.doit = ubcore_set_genl_pid_ops
	},
	{
		.cmd = UBCORE_CMD_UVS_INIT_RES,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.start = ubcore_get_uvs_init_res_start,
		.dumpit = ubcore_get_uvs_init_res_dump,
		.done = ubcore_get_uvs_init_res_done
	},
	{
		.cmd = UBCORE_CMD_TPF2FE_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tpf2fe_resp_ops,
	},
	{
		.cmd = UBCORE_CMD_RESTORE_TP_REQ,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tp_req_ops,
	},
	{
		.cmd = UBCORE_CMD_QUERY_TP_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tp_resp_ops,
	},
	{
		.cmd = UBCORE_CMD_RESTORE_TP_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tp_resp_ops,
	},
	{
		.cmd = UBCORE_CMD_ADD_SIP_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tp_resp_ops,
	},
	{
		.cmd = UBCORE_CMD_DEL_SIP_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_tp_resp_ops,
	},
	{
		.cmd = UBCORE_CMD_UPDATE_TPF_DEV_INFO_RESP,
		.validate = GENL_DONT_VALIDATE_STRICT | GENL_DONT_VALIDATE_DUMP,
		.doit = ubcore_update_tpf_dev_info_resp_ops,
	},
};

 /* ubcore family definition */

struct genl_family ubcore_genl_family __ro_after_init = {
	.hdrsize = 0,
	.name = UBCORE_GENL_FAMILY_NAME,
	.version = UBCORE_GENL_FAMILY_VERSION,
	.maxattr = UBCORE_ATTR_MAX,
	.policy = ubcore_policy,
	.netnsok = true,
	.module = THIS_MODULE,
	.ops = ubcore_genl_ops,
	.n_ops =  ARRAY_SIZE(ubcore_genl_ops)
};

int __init ubcore_genl_init(void)
{
	return genl_register_family(&ubcore_genl_family);
}

/* exit network namespace */
void ubcore_genl_exit(void)
{
	(void)genl_unregister_family(&ubcore_genl_family);
}
