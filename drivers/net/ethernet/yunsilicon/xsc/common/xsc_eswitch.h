/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __XSC_ESWITCH_H__
#define __XSC_ESWITCH_H__

#include "common/xsc_core.h"
#include "common/fs_core.h"

enum {
	XSC_ESWITCH_NONE,
	XSC_ESWITCH_LEGACY,
	XSC_ESWITCH_OFFLOADS
};

enum xsc_rep_mode {
	XSC_REP_MODE_INVALID,
	XSC_REP_MODE_KERNEL,
	XSC_REP_MODE_DPDK,
};

enum {
	REP_ETH,
	REP_IB,
	NUM_REP_TYPES,
};

enum {
	REP_UNREGISTERED,
	REP_REGISTERED,
	REP_LOADED,
};

enum xsc_switchdev_event {
	XSC_SWITCHDEV_EVENT_PAIR,
	XSC_SWITCHDEV_EVENT_UNPAIR,
};

enum {
	SET_VLAN_STRIP = BIT(0),
	SET_VLAN_INSERT = BIT(1),
	CLR_VLAN_STRIP = BIT(2),
	CLR_VLAN_INSERT = BIT(3),
};

struct xsc_eswitch_rep_data {
	void	*priv;
	atomic_t state;
};

struct xsc_eswitch_rep {
	struct xsc_eswitch_rep_data rep_data[NUM_REP_TYPES];
	u16	vport;
	struct	xsc_eswitch *esw;
};

struct xsc_eswitch_rep_ops {
	int (*load)(struct xsc_core_device *dev, struct xsc_eswitch_rep *rep);
	void (*unload)(struct xsc_eswitch_rep *rep);
	void *(*get_proto_dev)(struct xsc_eswitch_rep *rep);
	int (*event)(struct xsc_eswitch *esw,
		     struct xsc_eswitch_rep *rep,
		     enum xsc_switchdev_event event,
		     void *data);
};

struct xsc_eswitch_fdb {
	union {
		struct legacy_fdb {
			struct xsc_flow_table *fdb;
		} legacy;

		struct offloads_fdb {
			struct xsc_flow_namespace *ns;
			struct xsc_flow_table *tc_miss_table;
			struct xsc_flow_table *bypass_fdb;
			struct xsc_flow_group *miss_bypass_grp;
			struct xsc_flow_handle *miss_rule_bypass;
			struct xsc_flow_handle *miss_rule_bypass_uplink;
			struct xsc_flow_handle *peer_miss_rule_bypass;
			struct xsc_flow_handle *peer_miss_rule_bypass_uplink;
			struct xsc_flow_table *slow_fdb;
			struct xsc_flow_group *send_to_vport_grp;
			struct xsc_flow_group *send_to_vport_meta_grp;
			struct xsc_flow_group *peer_miss_grp;
			struct xsc_flow_handle **peer_miss_rules[XSC_MAX_PORTS];
			struct xsc_flow_group *miss_grp;
			struct xsc_flow_handle **send_to_vport_meta_rules;
			struct xsc_flow_handle *miss_rule_uni;
			struct xsc_flow_handle *miss_rule_multi;
			struct xsc_flow_table *miss_meter_fdb;
			struct xsc_flow_group *miss_meter_grp;
			struct xsc_flow_table *post_miss_meter_fdb;
			struct xsc_flow_group *post_miss_meter_grp;

			struct xsc_fs_chains *esw_chains_priv;
			struct {
				DECLARE_HASHTABLE(table, 8);
				/* Protects vports.table */
				struct mutex lock;
			} vports;

		} offloads;
	};
	u32 flags;
};

struct xsc_esw_offload {
	u8 rep_mode;
	bool rep_established;
	struct mutex uplink_netdev_lock; /* protects uplink_netdev */
	struct net_device *uplink_netdev;
	struct xsc_eswitch_rep *vport_reps;
	const struct xsc_eswitch_rep_ops *rep_ops[NUM_REP_TYPES];
	bool    host_funcs_disabled;

	struct xsc_flow_table *ft_offloads;
	struct xsc_flow_group *vport_rx_group;
	struct xsc_flow_group *vport_rx_drop_group;
	struct xsc_flow_handle *vport_rx_drop_rule;

	struct xsc_flow_table *ft_offloads_restore;
	struct xsc_flow_group *restore_group;
	struct xsc_modify_hdr *restore_copy_hdr_id;

	struct list_head peer_flows[XSC_MAX_PORTS];
	struct mutex peer_mutex; /* protects peer_flows */

	struct mutex encap_tbl_lock; /* protects encap_tbl */
	DECLARE_HASHTABLE(encap_tbl, 8);
	struct mutex decap_tbl_lock; /* protects decap_tbl */
	DECLARE_HASHTABLE(decap_tbl, 8);
	struct mod_hdr_tbl mod_hdr;
	DECLARE_HASHTABLE(termtbl_tbl, 8);
	struct mutex termtbl_mutex; /* protects termtbl hash */
	u8 inline_mode;
	atomic64_t num_flows;
	u64 num_block_encap;
	u64 num_block_mode;
};

/* hw feature bitmap, 32bit */
enum xsc_esw_ft_feature_flag {
	XSC_ESW_CAP_FT_SUPPORT,
	XSC_ESW_CAP_MULTI_FDB_ENCAP,
	XSC_ESW_CAP_IGNORE_FT_LEVEL,
	XSC_ESW_CAP_FT_METER_MISS,
	XSC_ESW_CAP_FT_MAX,
};

enum {
	XSC_COUNTER_SOURCE_ESWITCH = 0x0,
	XSC_COUNTER_FLOW_ESWITCH   = 0x1,
};

#define XSC_ESW_FT_CAP(params, flag) (!!((params).fdb_support & (BIT(flag))))

struct xsc_eswitch {
	struct xsc_core_device  *dev;
	struct xsc_eswitch_fdb fdb_table;

	u32     flags;
	int     total_vports;
	int     enabled_vports;
	int     num_vfs;
	struct xsc_vport        *vports;
	struct workqueue_struct *work_queue;

	/* Synchronize between vport change events
	 * and async SRIOV admin state changes
	 */
	struct mutex    state_lock;

	/* Protects eswitch mode changes occurring via sriov
	 * state change, devlink commands.
	 */
	struct rw_semaphore    mode_lock;
	atomic64_t user_count;

	int     mode;
	int     nvports;
	u16     manager_vport;
	u16     first_host_vport;

	struct xsc_esw_caps esw_caps;
	struct xsc_esw_offload offloads;
	bool     eswitch_operation_in_progress;
};

enum {
	XSC_MATCH_OUTER_HEADERS        = 1 << 0,
	XSC_MATCH_MISC_PARAMETERS      = 1 << 1,
	XSC_MATCH_INNER_HEADERS        = 1 << 2,
};

/* current maximum for flow based vport multicasting */
#define XSC_MAX_FLOW_FWD_VPORTS 32

enum {
	XSC_ESW_DEST_ENCAP         = BIT(0),
	XSC_ESW_DEST_ENCAP_VALID   = BIT(1),
	XSC_ESW_DEST_CHAIN_WITH_SRC_PORT_CHANGE  = BIT(2),
	XSC_ESW_DEST_LAG  = BIT(3),
};

struct xsc_esw_flow_attr {
	struct xsc_eswitch_rep *in_rep;
	struct xsc_core_device *in_xdev;
	struct xsc_core_device  *counter_dev;
#ifdef CONFIG_XSC_OFFLOAD_OVS
	struct xsc_tc_int_port *dest_int_port;
	struct xsc_tc_int_port *int_port;
#endif
	int split_count;
	int out_count;

	__be16  vlan_proto[XSC_FS_VLAN_DEPTH];
	u16     vlan_vid[XSC_FS_VLAN_DEPTH];
	u8      vlan_prio[XSC_FS_VLAN_DEPTH];
	u8      total_vlan;
	struct {
		u32 flags;
		bool vport_valid;
		u16 vport;
		struct xsc_pkt_reformat *pkt_reformat;
		struct xsc_core_device *xdev;
//		struct xsc_termtbl_handle *termtbl;
		int src_port_rewrite_act_id;
	} dests[XSC_MAX_FLOW_FWD_VPORTS];
	struct xsc_rx_tun_attr *rx_tun_attr;
	struct ethhdr eth;
	struct xsc_pkt_reformat *decap_pkt_reformat;
};

struct esw_vport_tbl_namespace {
	int max_fte;
	int max_num_groups;
	u32 flags;
};

struct xsc_vport_tbl_attr {
	u32 chain;
	u16 prio;
	u16 vport;
	struct esw_vport_tbl_namespace *vport_ns;
};

enum xsc_mapped_obj_type {
	XSC_MAPPED_OBJ_CHAIN,
	XSC_MAPPED_OBJ_SAMPLE,
	XSC_MAPPED_OBJ_INT_PORT_METADATA,
	XSC_MAPPED_OBJ_ACT_MISS,
};

struct xsc_mapped_obj {
	enum xsc_mapped_obj_type type;
	union {
		u32 chain;
		u64 act_miss_cookie;
		struct {
			u32 group_id;
			u32 rate;
			u32 trunc_size;
			u32 tunnel_id;
		} sample;
		u32 int_port_metadata;
	};
};

#define esw_chains(esw) \
	((esw)->fdb_table.offloads.esw_chains_priv)

static inline struct xsc_flow_table *
xsc_eswitch_get_slow_fdb(struct xsc_eswitch *esw)
{
	return esw->fdb_table.offloads.slow_fdb;
}

static inline struct xsc_flow_table *
xsc_eswitch_get_bypass_fdb(struct xsc_eswitch *esw)
{
	return esw->fdb_table.offloads.bypass_fdb;
}

static inline bool xsc_eswitch_vlan_actions_supported(struct xsc_core_device *dev,
						      u8 vlan_depth)
{
	bool ret = true;
	struct xsc_eswitch *esw = dev->priv.eswitch;

	if (vlan_depth == 1)
		return ret;

	return  ret && esw->esw_caps.pop_vlan_2 && esw->esw_caps.push_vlan_2;
}

bool is_xdev_switchdev_mode(const struct xsc_core_device *dev);
bool xsc_esw_hold(struct xsc_core_device *xdev);
void xsc_esw_get(struct xsc_core_device *xdev);
void xsc_esw_release(struct xsc_core_device *xdev);
void xsc_esw_put(struct xsc_core_device *xdev);

#define esw_info(dev, format, ...)                      \
	xsc_core_info(dev, "E-Switch: " format, ##__VA_ARGS__)

#define esw_err(dev, format, ...)                      \
	xsc_core_err(dev, "E-Switch: " format, ##__VA_ARGS__)

#define esw_warn(dev, format, ...)                      \
	xsc_core_warn(dev, "E-Switch: " format, ##__VA_ARGS__)

#define esw_debug(dev, format, ...)                     \
	xsc_core_dbg(dev, format, ##__VA_ARGS__)

#endif /* XSC_ESWITCH_H */
