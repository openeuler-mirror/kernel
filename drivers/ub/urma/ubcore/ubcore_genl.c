// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
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
#include <ub/urma/ubcore_api.h>
#include <ub/urma/ubcore_perf.h>
#include "ubcore_msg.h"
#include "ubcore_cmd.h"
#include "ubcore_device.h"
#include "ubcore_genl_admin.h"
#include "ubcore_genl_define.h"
#include "ubcore_netlink.h"
#include "ubcore_genl.h"

static const struct nla_policy ubcore_policy[NUM_UBCORE_ATTR] = {
	[UBCORE_ATTR_UNSPEC] = { 0 },
	[UBCORE_HDR_COMMAND] = { .type = NLA_U32 },
	[UBCORE_HDR_ARGS_LEN] = { .type = NLA_U32 },
	[UBCORE_HDR_ARGS_ADDR] = { .type = NLA_U64 },
	[UBCORE_ATTR_DEV_NS_MODE] = { .type = NLA_U8 },
	[UBCORE_ATTR_DEV_NAME] = { .type = NLA_STRING,
				   .len = UBCORE_MAX_DEV_NAME - 1 },
	[UBCORE_ATTR_NS_FD] = { .type = NLA_U32 },
	[UBCORE_ATTR_EID_IDX] = { .type = NLA_U16 },
	[UBCORE_MSG_SEQ] = { .type = NLA_U32 },
	[UBCORE_MSG_TYPE] = { .type = NLA_U32 },
	[UBCORE_TRANSPORT_TYPE] = { .type = NLA_U32 },
	[UBORE_SRC_ID] = { .len = UBCORE_EID_SIZE },
	[UBORE_DST_ID] = { .len = UBCORE_EID_SIZE },
	[UBCORE_PAYLOAD_DATA] = { .type = NLA_BINARY },
	[UBCORE_UPDATE_EID_RET] = { .type = NLA_S32 },
	[UBCORE_ATTR_EID] = { .type = NLA_BINARY, .len = UBCORE_EID_SIZE },
	[UBCORE_ATTR_MAIN_UE_EID] = { .type = NLA_BINARY,
				      .len = UBCORE_EID_SIZE },
	[UBCORE_ATTR_EID_NUM] = { .type = NLA_U32 },
	[UBCORE_ATTR_EID_LIST] = { .type = NLA_BINARY },
	[UBCORE_ATTR_STATUS] = { .type = NLA_S32 },
	[UBCORE_ATTR_EID_NS_MODE] = { .type = NLA_U8 },
	[UBCORE_ATTR_SL] = { .type = NLA_U32 },
	[UBCORE_ATTR_PRIORITY] = { .type = NLA_U32 },
	[UBCORE_ATTR_PERF_STAT] = { .type = NLA_BINARY,
				     .len = sizeof(struct ubcore_latency_stat) },
	[UBCORE_ATTR_TOOL_QUERY_KEY] = { .type = NLA_U32 },
	[UBCORE_ATTR_TOOL_QUERY_KEY_TYPE] = { .type = NLA_U32 },
	[UBCORE_ATTR_TOOL_QUERY_KEY_EXT] = { .type = NLA_U32 },
	[UBCORE_ATTR_TOOL_QUERY_KEY_CNT] = { .type = NLA_U32 },
	[UBCORE_ATTR_STATS] = { .type = NLA_BINARY,
				     .len = sizeof(struct ubcore_stats) },
	[UBCORE_ATTR_TPID_QUERY_FLAG] = { .type = NLA_U8 },
	[UBCORE_ATTR_TPID]            = { .type = NLA_U64 },
};

static const struct genl_ops ubcore_genl_ops[] = {
	{
		.cmd = UBCORE_CMD_QUERY_STATS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_query_stats_ops,
	},
	{
		.cmd = UBCORE_CMD_QUERY_RES,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.start = ubcore_query_res_start,
		.dumpit = ubcore_query_res_dump,
		.done = ubcore_query_res_done,
	},
	{
		.cmd = UBCORE_CMD_ADD_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.start = ubcore_add_eid_start,
		.dumpit = ubcore_add_eid_dump,
		.done = ubcore_add_eid_done,
	},
	{
		.cmd = UBCORE_CMD_DEL_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.start = ubcore_delete_eid_start,
		.dumpit = ubcore_delete_eid_dump,
		.done = ubcore_delete_eid_done,
	},
	{
		.cmd = UBCORE_CMD_SET_EID_MODE,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_eid_mode_ops,
	},
	{
		.cmd = UBCORE_CMD_SET_DEV_NS_MODE,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_dev_ns_mode_ops,
	},
	{
		.cmd = UBCORE_CMD_SET_DEV_NS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_dev_ns_ops,
	},
	{
		.cmd = UBCORE_CMD_EXPOSE_DEV_NS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_expose_dev_ns_ops,
	},
	{
		.cmd = UBCORE_CMD_UNEXPOSE_DEV_NS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_unexpose_dev_ns_ops,
	},
	{
		.cmd = UBCORE_CMD_SET_DEV_EID_NS,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_dev_eid_ns_ops,
	},
	{
		.cmd = UBCORE_CMD_SET_SL,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_set_sl,
	},
	{
		.cmd = UBCORE_CMD_ADMIN_INSERT_MAIN_UE_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_admin_insert_main_ue_eid,
	},
	{
		.cmd = UBCORE_CMD_ADMIN_DELETE_MAIN_UE_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_admin_delete_main_ue_eid,
	},
	{
		.cmd = UBCORE_CMD_ADMIN_LOOKUP_MAIN_UE_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_admin_lookup_main_ue_eid,
	},
	{
		.cmd = UBCORE_CMD_ADMIN_FLUSH_MAIN_UE_EID,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_admin_flush_main_ue_eid,
	},
	{
		.cmd = UBCORE_CMD_ADMIN_INSERT_MAIN_UE_EID_BATCH,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_admin_insert_main_ue_eid_batch,
	},
	{
		.cmd = UBCORE_CMD_PERF_START,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_perf_start_ops,
	},
	{
		.cmd = UBCORE_CMD_PERF_STOP,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_perf_stop_ops,
	},
	{
		.cmd = UBCORE_CMD_PERF_SHOW,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.doit = ubcore_perf_show_ops,
	},
	{ .cmd = UBCORE_CMD_SET_EID_NS_MODE,
	  .policy = ubcore_policy,
	  .maxattr = ARRAY_SIZE(ubcore_policy) - 1,
	  .flags = GENL_ADMIN_PERM,
	  .doit = ubcore_set_eid_ns_mode_ops,
	},
	{
		.cmd = UBCORE_CMD_SHOW_TPID_LIST,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.start = ubcore_show_tpid_list_start,
		.dumpit = ubcore_show_tpid_list_dump,
		.done = ubcore_show_tpid_list_done,
	},
	{
		.cmd = UBCORE_CMD_SHOW_TPID_REUSE,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.start = ubcore_show_tpid_reuse_start,
		.dumpit = ubcore_show_tpid_reuse_dump,
		.done = ubcore_show_tpid_reuse_done,
	},
	{
		.cmd = UBCORE_CMD_SHOW_SYSTEM,
		.policy = ubcore_policy,
		.maxattr = ARRAY_SIZE(ubcore_policy) - 1,
		.flags = GENL_ADMIN_PERM,
		.doit = ubcore_show_system_ops,
	},
};

/* ubcore family definition */

struct genl_family ubcore_genl_family __ro_after_init = {
	.hdrsize = 0,
	.name = UBCORE_GENL_FAMILY_NAME,
	.version = UBCORE_GENL_FAMILY_VERSION,
	.maxattr = UBCORE_ATTR_MAX,
	.policy = ubcore_policy,

	.resv_start_op = UBCORE_CMD_MAX,

	.netnsok = true,
	.module = THIS_MODULE,
	.ops = ubcore_genl_ops,
	.n_ops = ARRAY_SIZE(ubcore_genl_ops)
};

static int ubcore_nl_event_notifier_call(struct notifier_block *nb,
					 unsigned long action, void *data)
{
	struct netlink_notify *notify = data;

	if (action != NETLINK_URELEASE || notify == NULL ||
	    notify->protocol != NETLINK_GENERIC)
		return NOTIFY_DONE;

	return NOTIFY_DONE;
}

static struct notifier_block g_nl_notifier = {
	.notifier_call = ubcore_nl_event_notifier_call,
};

int __init ubcore_genl_init(void)
{
	int ret;

	ret = genl_register_family(&ubcore_genl_family);
	if (ret != 0)
		ubcore_log_err("Failed to ubcore genl init\n");

	return netlink_register_notifier(&g_nl_notifier);
}

/* exit network namespace */
void ubcore_genl_exit(void)
{
	(void)netlink_unregister_notifier(&g_nl_notifier);
	(void)genl_unregister_family(&ubcore_genl_family);
}
