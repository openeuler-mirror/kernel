/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef _XSC_FS_CORE_
#define _XSC_FS_CORE_

#include "common/device.h"
#include "../pci/xsc_flow.h"

#include <linux/refcount.h>
#include <linux/rhashtable.h>
#include <linux/llist.h>
#include <linux/rwsem.h>
#include <net/flow_offload.h>

struct xsc_ifc_flow_attr;

#define CONFIG_XSC_OFFLOAD_COUNTER	1

#define FDB_TC_MAX_CHAIN 2
#define FDB_FT_CHAIN (FDB_TC_MAX_CHAIN + 1)
#define FDB_TC_SLOW_PATH_CHAIN (FDB_FT_CHAIN + 1)

/* The index of the last real chain (FT) + 1 as chain zero is valid as well */
#define FDB_NUM_CHAINS (FDB_FT_CHAIN + 1)

#define FDB_TC_MAX_PRIO 128
#define FDB_TC_LEVELS_PER_PRIO 1

#define XSC_FS_DEFAULT_FLOW_TAG 0x0
#define XSC_FS_VLAN_DEPTH	2

#define MAX_FLOW_GROUP_SIZE BIT(8)
#define MAX_FTE_SZ BIT(15)

#define XSC_BY_PASS_NUM_REGULAR_PRIOS 64
#define XSC_BY_PASS_NUM_PRIOS (XSC_BY_PASS_NUM_REGULAR_PRIOS)

#ifndef sizeof_field
#define sizeof_field(TYPE, MEMBER) sizeof(((TYPE *)0)->(MEMBER))
#endif

#ifndef DECLARE_HASHTABLE
#define DECLARE_HASHTABLE(name, bits) \
	struct hlist_head name[1 << (bits)]
#endif

#ifndef struct_size
#define struct_size(p, member, n) \
	(sizeof(*(p)) + (n) * sizeof(*((p)->(member))))
#endif

#define XSC_SET_CFG(p, f, v) XSC_SET(create_flow_group_in, p, f, v)

enum xsc_flow_destination_type {
	XSC_FLOW_DESTINATION_TYPE_NONE,
	XSC_FLOW_DESTINATION_TYPE_VPORT,
	XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE,
	XSC_FLOW_DESTINATION_TYPE_TIR,
	XSC_FLOW_DESTINATION_TYPE_FLOW_SAMPLER,
	XSC_FLOW_DESTINATION_TYPE_UPLINK,
	XSC_FLOW_DESTINATION_TYPE_PORT,
	XSC_FLOW_DESTINATION_TYPE_COUNTER,
	XSC_FLOW_DESTINATION_TYPE_FLOW_TABLE_NUM,
	XSC_FLOW_DESTINATION_TYPE_RANGE,
	XSC_FLOW_DESTINATION_TYPE_TABLE_TYPE,
	XSC_FLOW_DESTINATION_TYPE_DEF_FLOW_TABLE,
	XSC_FLOW_DESTINATION_TYPE_FLOW_CHAIN,
};

enum {
	XSC_SET_FTE_MODIFY_ENABLE_MASK_ACTION    = 0x0,
	XSC_SET_FTE_MODIFY_ENABLE_MASK_FLOW_TAG  = 0x1,
	XSC_SET_FTE_MODIFY_ENABLE_MASK_DESTINATION_LIST    = 0x2,
	XSC_SET_FTE_MODIFY_ENABLE_MASK_FLOW_COUNTERS    = 0x3,
};

enum {
	XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_PRIO	= 1 << 16,
	XSC_FLOW_CONTEXT_ACTION_ENCRYPT	= 1 << 17,
	XSC_FLOW_CONTEXT_ACTION_DECRYPT	= 1 << 18,
	XSC_FLOW_CONTEXT_ACTION_FWD_NEXT_NS	= 1 << 19,
};

enum {
	XSC_FLOW_TABLE_TUNNEL_EN_REFORMAT = BIT(0),
	XSC_FLOW_TABLE_TUNNEL_EN_DECAP = BIT(1),
	XSC_FLOW_TABLE_TERMINATION = BIT(2),
	XSC_FLOW_TABLE_UNMANAGED = BIT(3),
	XSC_FLOW_TABLE_OTHER_VPORT = BIT(4),
	XSC_FLOW_TABLE_UPLINK_VPORT = BIT(5),
};

enum xsc_flow_namespace_type {
	XSC_FLOW_NAMESPACE_BYPASS,
	XSC_FLOW_NAMESPACE_LAG,
	XSC_FLOW_NAMESPACE_OFFLOADS,
	XSC_FLOW_NAMESPACE_KERNEL,
	XSC_FLOW_NAMESPACE_FDB_BYPASS,
	XSC_FLOW_NAMESPACE_FDB,
};

enum {
	FDB_BYPASS_PATH,
	FDB_TC_OFFLOAD,
	FDB_FT_OFFLOAD,
	FDB_TC_MISS,
	FDB_MISS_METER,
	FDB_BR_OFFLOAD,
	FDB_SLOW_PATH,
	FDB_PER_VPORT,
};

enum {
	FLOW_CONTEXT_HAS_TAG = BIT(0),
	FLOW_CONTEXT_UPLINK_HAIRPIN_EN = BIT(1),
};

/* FS_TYPE_PRIO_CHAINS is a PRIO that will have namespaces only,
 * and those are in parallel to one another when going over them to connect
 * a new flow table. Meaning the last flow table in a TYPE_PRIO prio in one
 * parallel namespace will not automatically connect to the first flow table
 * found in any prio in any next namespace, but skip the entire containing
 * TYPE_PRIO_CHAINS prio.
 *
 * This is used to implement tc chains, each chain of prios is a different
 * namespace inside a containing TYPE_PRIO_CHAINS prio.
 */

enum fs_node_type {
	FS_TYPE_NAMESPACE,
	FS_TYPE_PRIO,
	FS_TYPE_PRIO_CHAINS,
	FS_TYPE_FLOW_TABLE,
	FS_TYPE_FLOW_GROUP,
	FS_TYPE_FLOW_ENTRY,
	FS_TYPE_FLOW_DEST
};

enum fs_flow_table_type {
	FS_FT_NIC_RX          = 0x0,
	FS_FT_FDB             = 0x1,
	FS_FT_MAX_TYPE,
};

enum fs_flow_table_op_mod {
	FS_FT_OP_MOD_NORMAL,
	FS_FT_OP_MOD_LAG_DEMUX,
};

enum fs_fte_status {
	FS_FTE_STATUS_EXISTING = 1UL << 0,
};

enum xsc_flow_steering_mode {
	XSC_FLOW_STEERING_MODE_DMFS,
	XSC_FLOW_STEERING_MODE_SMFS
};

enum xsc_flow_steering_capabilty {
	XSC_FLOW_STEERING_CAP_VLAN_PUSH_ON_RX = 1UL << 0,
	XSC_FLOW_STEERING_CAP_VLAN_POP_ON_TX = 1UL << 1,
	XSC_FLOW_STEERING_CAP_MATCH_RANGES = 1UL << 2,
};

enum xsc_flow_table_miss_action {
	XSC_FLOW_TABLE_MISS_ACTION_DEF,
	XSC_FLOW_TABLE_MISS_ACTION_FWD,
};

enum xsc_flow_resource_owner {
	XSC_FLOW_RESOURCE_OWNER_FW,
	XSC_FLOW_RESOURCE_OWNER_SW,
};

enum {
	XSC_FLOW_DEST_VPORT_VHCA_ID      = BIT(0),
	XSC_FLOW_DEST_VPORT_REFORMAT_ID  = BIT(1),
	XSC_FLOW_DEST_VPORT_LAG_ID  = BIT(2),
};

enum xsc_flow_dest_range_field {
	XSC_FLOW_DEST_RANGE_FIELD_PKT_LEN = 0,
};

enum {
	FLOW_ACT_NO_APPEND = BIT(0),
	FLOW_ACT_IGNORE_FLOW_LEVEL = BIT(1),
};

#define XSC_DECLARE_FLOW_ACT(name) \
	struct xsc_flow_act name = { .action = XSC_FLOW_CONTEXT_ACTION_FWD_DEST,\
				     .flags = 0, }

struct xsc_flow_definer {
	enum xsc_flow_namespace_type ns_type;
	u32 id;
};

struct xsc_modify_hdr {
	enum xsc_flow_namespace_type ns_type;
	enum xsc_flow_resource_owner owner;
	u32 id;
};

struct xsc_pkt_reformat {
	enum xsc_flow_namespace_type ns_type;
	int reformat_type; /* from xsc_ifc */
	enum xsc_flow_resource_owner owner;
	u32 id;
};

struct xsc_pkt_reformat_params {
	int type;
	u8 param_0;
	u8 param_1;
	size_t size;
	void *data;
};

struct xsc_flow_steering {
	struct xsc_core_device		*dev;
	enum xsc_flow_steering_mode	mode;
	struct kmem_cache		*fgs_cache;
	struct kmem_cache               *ftes_cache;
	struct xsc_flow_root_namespace  *root_ns;
	struct xsc_flow_root_namespace  *fdb_root_ns;
	struct xsc_flow_namespace	**fdb_sub_ns;
};

struct fs_node {
	struct list_head	list;
	struct list_head	children;
	enum fs_node_type	type;
	struct fs_node		*parent;
	struct fs_node		*root;
	/* lock the node for writing and traversing */
	struct rw_semaphore	lock;
	refcount_t		refcount;
	bool			active;
	void (*del_hw_func)(struct fs_node *node);
	void (*del_sw_func)(struct fs_node *node);
	atomic_t		version;
};

struct xsc_flow_destination {
	enum xsc_flow_destination_type	type;
	union {
		u32			tir_num;
		u32			ft_num;
		struct xsc_flow_table	*ft;
		u32			counter_id;
		struct {
			u16		num;
			u16		vhca_id;
			u8		flags;
			struct xsc_pkt_reformat *pkt_reformat;
		} vport;
		struct {
			struct xsc_flow_table         *hit_ft;
			struct xsc_flow_table         *miss_ft;
			enum xsc_flow_dest_range_field field;
			u32                             min;
			u32                             max;
		} range;
		u32			sampler_id;
	};
};

struct xsc_flow_rule {
	struct fs_node			node;
	struct xsc_flow_table		*ft;
	struct xsc_flow_destination	dest_attr;
	/* next_ft should be accessed under chain_lock and only of
	 * destination type is FWD_NEXT_fT.
	 */
	struct list_head		next_ft;
	u32				sw_action;
};

struct xsc_flow_handle {
	int num_rules;
	struct xsc_flow_rule *rule[];
};

/* Type of children is xsc_flow_group */
struct xsc_flow_table {
	struct fs_node			node;
	u32				id;
	u16				vport;
	unsigned int			max_fte;
	unsigned int			chain;
	unsigned int			prio;
	unsigned int			level;
	enum fs_flow_table_type		type;
	enum fs_flow_table_op_mod	op_mod;
	struct {
		bool			active;
		unsigned int		required_groups;
		unsigned int		group_size;
		unsigned int		num_groups;
		unsigned int		max_fte;
	} autogroup;
	/* Protect fwd_rules */
	struct mutex			lock;
	/* FWD rules that point on this flow table */
	struct list_head		fwd_rules;
	u32				flags;
	struct rhltable			fgs_hash;
	enum xsc_flow_table_miss_action def_miss_action;
	struct xsc_flow_namespace	*ns;
};

struct xsc_ft_underlay_qp {
	struct list_head list;
	u32 qpn;
};

#define XSC_ST_SZ_DW_MATCH_PARAM (XSC_ST_SZ_DW(fte_match_param))
#define XSC_ST_SZ_DW_FTE_MATCH (XSC_ST_SZ_DW(fte_match))

/* Type of children is xsc_flow_rule */

struct xsc_flow_context {
	u32 flags;
	u32 flow_tag;
	u32 flow_source;
};

struct xsc_fs_vlan {
	u16 ethtype;
	u16 vid;
	u8  prio;
};

struct xsc_exe_aso {
	u32 object_id;
	u8 type;
	u8 return_reg_id;
	union {
		u32 ctrl_data;
		struct {
			u8 meter_idx;
			u8 init_color;
		} flow_meter;
	};
};

struct xsc_fc_cache {
	u64 packets;
	u64 bytes;
	u64 lastuse;
};

struct xsc_fc {
	struct list_head list;
	struct llist_node addlist;
	struct llist_node dellist;

	/* last{packets,bytes} members are used when calculating the delta since
	 * last reading
	 */
	u64 lastpackets;
	u64 lastbytes;

	struct xsc_fc_bulk *bulk;
	u32 id;
	bool aging;

	struct xsc_fc_cache cache ____cacheline_aligned_in_smp;
};

struct xsc_fc_bulk {
	struct list_head pool_list;
	u32 base_id;
	u32 bulk_len;
	unsigned long *bitmask;
	struct xsc_fc fcs[];
};

struct xsc_flow_act {
	u32 action;
	struct xsc_modify_hdr *modify_hdr;
	struct xsc_mod_hdr_handle *mh;
	struct xsc_pkt_reformat *pkt_reformat;
	u32 flags;
	struct xsc_fs_vlan vlan[XSC_FS_VLAN_DEPTH];
	struct xsc_flow_group *fg;
	struct xsc_exe_aso exe_aso;
};

struct fs_fte {
	struct fs_node			node;
	u32				val[XSC_ST_SZ_DW_FTE_MATCH];
	u32				dests_size;
	u32				fwd_dests;
	u32				index;
	u32				hw_index;
	struct xsc_flow_context		flow_context;
	struct xsc_flow_act		action;
	enum fs_fte_status		status;
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	struct xsc_fc			*counter;
#endif
	struct rhash_head		hash;
	int				modify_mask;
};

/* Type of children is xsc_flow_table/namespace */
struct fs_prio {
	struct fs_node			node;
	unsigned int			num_levels;
	unsigned int			start_level;
	unsigned int			prio;
	unsigned int			num_ft;
};

/* Type of children is fs_prio */
struct xsc_flow_namespace {
	/* parent == NULL => root ns */
	struct	fs_node			node;
	enum xsc_flow_table_miss_action def_miss_action;
};

struct xsc_flow_group_mask {
	u8	match_mask_enable;
	struct xsc_ifc_flow_attr	match_attr;
	u32	match_mask[XSC_ST_SZ_DW_MATCH_PARAM];
};

/* Type of children is fs_fte */
struct xsc_flow_group {
	struct fs_node			node;
	struct xsc_flow_group_mask	mask;
	u32				start_index;
	u32				max_ftes;
	struct ida			fte_allocator;
	u32				id;
	struct rhashtable		ftes_hash;
	struct rhlist_head		hash;
};

struct xsc_flow_root_namespace {
	struct xsc_flow_namespace	ns;
	enum   xsc_flow_steering_mode	mode;
	enum   fs_flow_table_type	table_type;
	struct xsc_core_device		*dev;
	struct xsc_flow_table		*root_ft;
	/* Should be held when chaining flow tables */
	struct mutex			chain_lock;
	struct list_head		underlay_qpns;
	const struct xsc_flow_cmds	*cmds;
};

#define LEFTOVERS_RULE_NUM	 2
static inline void build_leftovers_ft_param(int *priority,
					    int *n_ent,
					    int *n_grp)
{
	*priority = 0; /* Priority of leftovers_prio-0 */
	*n_ent = LEFTOVERS_RULE_NUM;
	*n_grp = LEFTOVERS_RULE_NUM;
}

struct xsc_flow_spec {
	u8   match_mask_enable;
	struct xsc_ifc_flow_attr match_attr;
	u32  match_mask[XSC_ST_SZ_DW(fte_match_param)];
	u32  match_value[XSC_ST_SZ_DW(fte_match_param)];
	struct xsc_flow_context flow_context;
};

struct mod_hdr_tbl {
	struct mutex lock; /* protects hlist */
	DECLARE_HASHTABLE(hlist, 8);
};

struct xsc_flow_namespace *
xsc_get_fdb_sub_ns(struct xsc_core_device *dev, int n);
struct xsc_flow_namespace *
xsc_get_flow_namespace(struct xsc_core_device *dev, enum xsc_flow_namespace_type type);

struct xsc_flow_table_attr {
	int prio;
	int max_fte;
	u32 level;
	u32 flags;
	u16 uid;
	struct xsc_flow_table *next_ft;

	struct {
		int max_num_groups;
		int num_reserved_entries;
	} autogroup;
};

struct xsc_flow_table *
xsc_create_flow_table(struct xsc_flow_namespace *ns, struct xsc_flow_table_attr *ft_attr);

struct xsc_flow_table *
xsc_create_auto_grouped_flow_table(struct xsc_flow_namespace *ns,
				   struct xsc_flow_table_attr *ft_attr);

struct xsc_flow_table *
xsc_create_vport_flow_table(struct xsc_flow_namespace *ns,
			    struct xsc_flow_table_attr *ft_attr, u16 vport);
struct xsc_flow_table *xsc_create_lag_demux_flow_table(struct xsc_flow_namespace *ns,
						       int prio, u32 level);
int xsc_destroy_flow_table(struct xsc_flow_table *ft);

/* inbox should be set with the following values:
 * start_flow_index
 * end_flow_index
 * match_mask_enable
 * match_mask
 */
struct xsc_flow_group *
xsc_create_flow_group(struct xsc_flow_table *ft, u32 *in);
void xsc_destroy_flow_group(struct xsc_flow_group *fg);

/* Single destination per rule.
 * Group ID is implied by the match criteria.
 */
struct xsc_flow_handle *
xsc_add_flow_rules(struct xsc_flow_table *ft, const struct xsc_flow_spec *spec,
		   struct xsc_flow_act *flow_act, struct xsc_flow_destination *dest,
		   int num_dest);
void xsc_del_flow_rules(struct xsc_flow_handle *fr);

int xsc_modify_rule_destination(struct xsc_flow_handle *handler,
				struct xsc_flow_destination *new_dest,
				struct xsc_flow_destination *old_dest);

struct xsc_modify_hdr *xsc_modify_header_alloc(struct xsc_core_device *dev,
					       u8 ns_type, u8 num_actions,
					       void *modify_actions);
void xsc_modify_header_dealloc(struct xsc_core_device *dev,
			       struct xsc_modify_hdr *modify_hdr);

struct xsc_pkt_reformat *xsc_packet_reformat_alloc(struct xsc_core_device *dev,
						   struct xsc_pkt_reformat_params *params,
						   enum xsc_flow_namespace_type ns_type);
void xsc_packet_reformat_dealloc(struct xsc_core_device *dev,
				 struct xsc_pkt_reformat *reformat);

u32 xsc_flow_table_id(struct xsc_flow_table *ft);

int xsc_flow_namespace_set_peer(struct xsc_flow_root_namespace *ns,
				struct xsc_flow_root_namespace *peer_ns,
				u16 peer_vhca_id);

int xsc_flow_namespace_set_mode(struct xsc_flow_namespace *ns,
				enum xsc_flow_steering_mode mode);

int xsc_fs_core_alloc(struct xsc_core_device *dev);
void xsc_fs_core_free(struct xsc_core_device *dev);
int xsc_fs_core_init(struct xsc_core_device *dev);
void xsc_fs_core_cleanup(struct xsc_core_device *dev);

u32 xsc_fs_get_capabilities(struct xsc_core_device *dev, enum xsc_flow_namespace_type type);

struct xsc_flow_handle *add_to_miss_fg(struct xsc_flow_table *ft,
				       struct xsc_flow_group *fg,
				       const struct xsc_flow_spec *spec,
				       struct xsc_flow_act *flow_act,
				       struct xsc_flow_destination *dest,
				       int dest_num);

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
int xsc_init_fc_stats(struct xsc_core_device *dev);
void xsc_cleanup_fc_stats(struct xsc_core_device *dev);
void xsc_fc_queue_stats_work(struct xsc_core_device *dev, struct delayed_work *dwork,
			     unsigned long delay);
void xsc_fc_update_sampling_interval(struct xsc_core_device *dev,
				     unsigned long interval);

struct xsc_fc *xsc_fc_create(struct xsc_core_device *dev, bool aging);

void xsc_fc_destroy(struct xsc_core_device *dev, struct xsc_fc *counter);
u64 xsc_fc_query_lastuse(struct xsc_fc *counter);
void xsc_fc_query_cached(struct xsc_fc *counter,
			 u64 *bytes, u64 *packets, u64 *lastuse);
void xsc_fc_query_cached_raw(struct xsc_fc *counter,
			     u64 *bytes, u64 *packets, u64 *lastuse);
int xsc_fc_query(struct xsc_core_device *dev, struct xsc_fc *counter,
		 u64 *packets, u64 *bytes);
int xsc_fc_query_and_clear(struct xsc_core_device *dev, struct xsc_fc *counter,
			   u64 *packets, u64 *bytes);
u32 xsc_fc_id(struct xsc_fc *counter);

int xsc_fs_add_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn);
int xsc_fs_remove_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn);
#endif

int xsc_fs_add_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn);
int xsc_fs_remove_rx_underlay_qpn(struct xsc_core_device *dev, u32 underlay_qpn);

struct xsc_flow_root_namespace *find_root(struct fs_node *node);

#define fs_get_obj(v, _node)  {v = container_of((_node), typeof(*v), node); }

#define fs_list_for_each_entry(pos, root)		\
	list_for_each_entry(pos, root, node.list)

#define fs_list_for_each_entry_safe(pos, tmp, root)		\
	list_for_each_entry_safe(pos, tmp, root, node.list)

#define fs_for_each_ns_or_ft_reverse(pos, prio)				\
	list_for_each_entry_reverse(pos, &(prio)->node.children, list)

#define fs_for_each_ns_or_ft(pos, prio)					\
	list_for_each_entry(pos, (&(prio)->node.children), list)

#define fs_for_each_prio(pos, ns)			\
	fs_list_for_each_entry(pos, &(ns)->node.children)

#define fs_for_each_ns(pos, prio)			\
	fs_list_for_each_entry(pos, &(prio)->node.children)

#define fs_for_each_ft(pos, prio)			\
	fs_list_for_each_entry(pos, &(prio)->node.children)

#define fs_for_each_ft_safe(pos, tmp, prio)			\
	fs_list_for_each_entry_safe(pos, tmp, &(prio)->node.children)

#define fs_for_each_fg(pos, ft)			\
	fs_list_for_each_entry(pos, &(ft)->node.children)

#define fs_for_each_fte(pos, fg)			\
	fs_list_for_each_entry(pos, &(fg)->node.children)

#define fs_for_each_dst(pos, fte)			\
	fs_list_for_each_entry(pos, &(fte)->node.children)

#endif
