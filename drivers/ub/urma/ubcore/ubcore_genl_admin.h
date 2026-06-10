/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2024-2025. All rights reserved.
 *
 * Description: define hash table ops for admin
 * Author: Zhao Yanchao
 * Create: 2024-01-18
 * Note:
 * History: 2024-01-18  Zhao Yanchao
 */

#ifndef UBCORE_GENL_ADMIN_H
#define UBCORE_GENL_ADMIN_H

#include <net/genetlink.h>

int ubcore_show_utp_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_query_stats_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_query_res_start(struct netlink_callback *cb);
int ubcore_query_res_dump(struct sk_buff *skb, struct netlink_callback *cb);
int ubcore_query_res_done(struct netlink_callback *cb);
int ubcore_set_eid_mode_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_set_dev_ns_mode_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_set_eid_ns_mode_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_expose_dev_ns_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_unexpose_dev_ns_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_set_dev_eid_ns_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_get_topo_info(struct sk_buff *skb, struct genl_info *info);
int ubcore_set_dev_ns_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_add_eid_start(struct netlink_callback *cb);
int ubcore_add_eid_dump(struct sk_buff *skb, struct netlink_callback *cb);
int ubcore_add_eid_done(struct netlink_callback *cb);
int ubcore_delete_eid_start(struct netlink_callback *cb);
int ubcore_delete_eid_done(struct netlink_callback *cb);
int ubcore_delete_eid_dump(struct sk_buff *skb, struct netlink_callback *cb);
int ubcore_set_sl(struct sk_buff *skb, struct genl_info *info);
int ubcore_admin_insert_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info);
int ubcore_admin_delete_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info);
int ubcore_admin_lookup_main_ue_eid(struct sk_buff *skb,
				    struct genl_info *info);
int ubcore_admin_flush_main_ue_eid(struct sk_buff *skb,
				   struct genl_info *info);
int ubcore_admin_insert_main_ue_eid_batch(struct sk_buff *skb,
					  struct genl_info *info);
int ubcore_get_v2p_res(struct sk_buff *skb, struct genl_info *info);
int ubcore_perf_start_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_perf_stop_ops(struct sk_buff *skb, struct genl_info *info);
int ubcore_perf_show_ops(struct sk_buff *skb, struct genl_info *info);

int ubcore_show_tpid_list_start(struct netlink_callback *cb);
int ubcore_show_tpid_list_dump(struct sk_buff *skb, struct netlink_callback *cb);
int ubcore_show_tpid_list_done(struct netlink_callback *cb);

int ubcore_show_tpid_reuse_start(struct netlink_callback *cb);
int ubcore_show_tpid_reuse_dump(struct sk_buff *skb, struct netlink_callback *cb);
int ubcore_show_tpid_reuse_done(struct netlink_callback *cb);

extern struct genl_family ubcore_genl_family;

#endif // UBCORE_GENERIC_NETLINK_ADMIN_H
