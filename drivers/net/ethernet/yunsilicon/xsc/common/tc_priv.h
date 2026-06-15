/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __TC_PRIV_H__
#define __TC_PRIV_H__

#include "mod_hdr.h"
#include "common/tc_flow.h"
#include "../net/tc/act/act.h"
#include "../net/tc/act/pedit.h"

#define XSC_TC_MAX_SPLITS 1

enum {
	XSC_TC_FLAG_INGRESS_BIT,
	XSC_TC_FLAG_EGRESS_BIT,
	XSC_TC_FLAG_NIC_OFFLOAD_BIT,
	XSC_TC_FLAG_ESW_OFFLOAD_BIT,
	XSC_TC_FLAG_FT_OFFLOAD_BIT,
	XSC_TC_FLAG_LAST_EXPORTED_BIT = XSC_TC_FLAG_FT_OFFLOAD_BIT,
};

#define XSC_TC_FLAG(flag) BIT(XSC_TC_FLAG_##flag##_BIT)

#define XSC_TC_FLOW_BASE (XSC_TC_FLAG_LAST_EXPORTED_BIT + 1)

enum {
	XSC_TC_FLOW_FLAG_INGRESS               = XSC_TC_FLAG_INGRESS_BIT,
	XSC_TC_FLOW_FLAG_EGRESS                = XSC_TC_FLAG_EGRESS_BIT,
	XSC_TC_FLOW_FLAG_ESWITCH               = XSC_TC_FLAG_ESW_OFFLOAD_BIT,
	XSC_TC_FLOW_FLAG_FT                    = XSC_TC_FLAG_FT_OFFLOAD_BIT,
	XSC_TC_FLOW_FLAG_NIC                   = XSC_TC_FLAG_NIC_OFFLOAD_BIT,
	XSC_TC_FLOW_FLAG_OFFLOADED             = XSC_TC_FLOW_BASE,
	XSC_TC_FLOW_FLAG_HAIRPIN               = XSC_TC_FLOW_BASE + 1,
	XSC_TC_FLOW_FLAG_HAIRPIN_RSS           = XSC_TC_FLOW_BASE + 2,
	XSC_TC_FLOW_FLAG_SLOW                  = XSC_TC_FLOW_BASE + 3,
	XSC_TC_FLOW_FLAG_DUP                   = XSC_TC_FLOW_BASE + 4,
	XSC_TC_FLOW_FLAG_NOT_READY             = XSC_TC_FLOW_BASE + 5,
	XSC_TC_FLOW_FLAG_DELETED               = XSC_TC_FLOW_BASE + 6,
	XSC_TC_FLOW_FLAG_L3_TO_L2_DECAP        = XSC_TC_FLOW_BASE + 7,
	XSC_TC_FLOW_FLAG_TUN_RX                = XSC_TC_FLOW_BASE + 8,
	XSC_TC_FLOW_FLAG_FAILED                = XSC_TC_FLOW_BASE + 9,
	XSC_TC_FLOW_FLAG_SAMPLE                = XSC_TC_FLOW_BASE + 10,
	XSC_TC_FLOW_FLAG_USE_ACT_STATS         = XSC_TC_FLOW_BASE + 11,
};

enum {
	XSC_ACTION_TYPE_SET   = 0x1,
	XSC_ACTION_TYPE_ADD   = 0x2,
	XSC_ACTION_TYPE_COPY  = 0x3,
};

struct xsc_tc_flow_parse_attr {
	const struct ip_tunnel_info *tun_info[XSC_MAX_FLOW_FWD_VPORTS];
	struct net_device *filter_dev;
	struct xsc_flow_spec spec;
	struct pedit_headers_action hdrs[__PEDIT_CMD_MAX];
	struct xsc_tc_mod_hdr_acts mod_hdr_acts;
	int mirred_ifindex[XSC_MAX_FLOW_FWD_VPORTS];
	struct xsc_tc_act_parse_state parse_state;
};

/* Helper struct for accessing a struct containing list_head array.
 * Containing struct
 *   |- Helper array
 *      [0] Helper item 0
 *          |- list_head item 0
 *          |- index (0)
 *      [1] Helper item 1
 *          |- list_head item 1
 *          |- index (1)
 * To access the containing struct from one of the list_head items:
 * 1. Get the helper item from the list_head item using
 *    helper item =
 *        container_of(list_head item, helper struct type, list_head field)
 * 2. Get the contining struct from the helper item and its index in the array:
 *    containing struct =
 *        container_of(helper item, containing struct type, helper field[index])
 */
struct encap_flow_item {
	struct xsc_encap_entry *e; /* attached encap instance */
	struct list_head list;
	int index;
};

struct encap_route_flow_item {
	struct xsc_route_entry *r; /* attached route instance */
	int index;
};

struct xsc_tc_flow {
	struct rhash_head node;
	struct xsc_adapter *priv;
	u64 cookie;
	unsigned long flags;
	struct xsc_flow_handle *rule[XSC_TC_MAX_SPLITS + 1];

	/* flows sharing same route entry */
	struct list_head decap_routes;
	struct xsc_route_entry *decap_route;
	struct encap_route_flow_item encap_routes[XSC_MAX_FLOW_FWD_VPORTS];

	/* Flow can be associated with multiple encap IDs.
	 * The number of encaps is bounded by the number of supported
	 * destinations.
	 */
	struct encap_flow_item encaps[XSC_MAX_FLOW_FWD_VPORTS];
	struct list_head peer[XSC_MAX_PORTS];    /* flows with peer flow */
	struct list_head unready; /* flows not ready to be offloaded (e.g
				   * due to missing route)
				   */
	struct list_head peer_flows; /* flows on peer */
	struct net_device *orig_dev; /* netdev adding flow first */
	int tmp_entry_index;
	struct list_head tmp_list; /* temporary flow list used by neigh update */
	refcount_t refcnt;
	struct rcu_head rcu_head;
	struct completion init_done;
	struct completion del_hw_done;
	struct xsc_flow_attr *attr;
	struct list_head attrs;
	u32 chain_mapping;
};

struct xsc_flow_handle *
xsc_tc_rule_offload(struct xsc_adapter *priv,
		    struct xsc_flow_spec *spec,
		    struct xsc_flow_attr *attr);

void
xsc_tc_rule_unoffload(struct xsc_adapter *priv,
		      struct xsc_flow_handle *rule,
		      struct xsc_flow_attr *attr);

u8 xsc_tc_get_ip_version(struct xsc_flow_spec *spec, bool outer);

struct xsc_flow_handle *
xsc_tc_offload_fdb_rules(struct xsc_eswitch *esw,
			 struct xsc_tc_flow *flow,
			 struct xsc_flow_spec *spec,
			 struct xsc_flow_attr *attr);

struct xsc_flow_attr *
xsc_tc_get_encap_attr(struct xsc_tc_flow *flow);

void xsc_tc_unoffload_flow_post_acts(struct xsc_tc_flow *flow);
int xsc_tc_offload_flow_post_acts(struct xsc_tc_flow *flow);

bool xsc_is_eswitch_flow(struct xsc_tc_flow *flow);
bool xsc_is_ft_flow(struct xsc_tc_flow *flow);
bool xsc_is_offloaded_flow(struct xsc_tc_flow *flow);
enum xsc_flow_namespace_type xsc_get_flow_namespace_id(struct xsc_tc_flow *flow);
bool xsc_same_hw_devs(struct xsc_adapter *priv, struct xsc_adapter *peer_priv);
u64 xsc_query_nic_system_image_guid(struct xsc_core_device *xdev);

static inline void __flow_flag_set(struct xsc_tc_flow *flow, unsigned long flag)
{
	/* Complete all memory stores before setting bit. */
	smp_mb__before_atomic();
	set_bit(flag, &flow->flags);
}

#define flow_flag_set(flow, flag) __flow_flag_set(flow, XSC_TC_FLOW_FLAG_##flag)

static inline bool __flow_flag_test_and_set(struct xsc_tc_flow *flow,
					    unsigned long flag)
{
	/* test_and_set_bit() provides all necessary barriers */
	return test_and_set_bit(flag, &flow->flags);
}

#define flow_flag_test_and_set(flow, flag)			\
	__flow_flag_test_and_set(flow,				\
				 XSC_TC_FLOW_FLAG_##flag)

static inline void __flow_flag_clear(struct xsc_tc_flow *flow, unsigned long flag)
{
	/* Complete all memory stores before clearing bit. */
	smp_mb__before_atomic();
	clear_bit(flag, &flow->flags);
}

#define flow_flag_clear(flow, flag) __flow_flag_clear(flow,		\
						      XSC_TC_FLOW_FLAG_##flag)

static inline bool __flow_flag_test(struct xsc_tc_flow *flow, unsigned long flag)
{
	bool ret = test_bit(flag, &flow->flags);

	/* Read fields of flow structure only after checking flags. */
	smp_mb__after_atomic();
	return ret;
}

#define flow_flag_test(flow, flag) __flow_flag_test(flow,		\
						    XSC_TC_FLOW_FLAG_##flag)

void xsc_tc_unoffload_from_slow_path(struct xsc_eswitch *esw,
				     struct xsc_tc_flow *flow);
struct xsc_flow_handle *
xsc_tc_offload_to_slow_path(struct xsc_eswitch *esw,
			    struct xsc_tc_flow *flow,
			    struct xsc_flow_spec *spec);

void xsc_tc_unoffload_fdb_rules(struct xsc_eswitch *esw,
				struct xsc_tc_flow *flow,
				struct xsc_flow_attr *attr);

struct xsc_tc_flow *xsc_flow_get(struct xsc_tc_flow *flow);
void xsc_flow_put(struct xsc_adapter *priv, struct xsc_tc_flow *flow);

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
struct xsc_fc *xsc_tc_get_counter(struct xsc_tc_flow *flow);
#endif

#ifdef CONFIG_XSC_OFFLOAD_OVS
struct xsc_tc_int_port_priv *
xsc_get_int_port_priv(struct xsc_adapter *priv);
#endif

#ifdef CONFIG_XSC_OFFLOAD_METER
struct xsc_flow_meters *xsc_get_flow_meters(struct xsc_core_device *dev);
#endif

void *xsc_get_match_headers_value(u32 flags, struct xsc_flow_spec *spec);
void *xsc_get_match_headers_criteria(u32 flags, struct xsc_flow_spec *spec);

#endif /* __XSC_EN_TC_PRIV_H__ */
