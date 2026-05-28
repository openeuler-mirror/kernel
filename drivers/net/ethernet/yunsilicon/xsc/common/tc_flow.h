/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2021 - 2023, Shanghai Yunsilicon Technology Co., Ltd.
 * All rights reserved.
 */

#ifndef __TC_FLOW_H__
#define __TC_FLOW_H__

#include <net/pkt_cls.h>
#include "tc_tun.h"
#include "common/mod_hdr.h"
#include "common/xsc_eswitch.h"
#include "common/fs_core.h"

struct xsc_tc_flow;
struct xsc_rep_uplink_priv;
struct xsc_esw_flow_attr;
struct pedit_headers_action;
struct xsc_esw_flow_attr;

#define XSC_TC_FLOW_ID_MASK 0x0000ffff

#define FLOW_DISSECTOR_MATCH(__rule, __type, __out_) do {			\
	const struct flow_match *__m = &(__rule)->match;			\
	struct flow_dissector *__d = (__m)->dissector;				\
										\
	(__out)->key = skb_flow_dissector_target(__d, __type, (__m)->key);	\
	(__out)->mask = skb_flow_dissector_target(__d, __type, (__m)->mask);	\
} while (0)

#define NIC_FLOW_ATTR_SZ (sizeof(struct xsc_flow_attr) +\
			  sizeof(struct xsc_nic_flow_attr))
#define ESW_FLOW_ATTR_SZ (sizeof(struct xsc_flow_attr) +\
			  sizeof(struct xsc_esw_flow_attr))
#define ns_to_attr_sz(ns) (((ns) == XSC_FLOW_NAMESPACE_FDB) ?\
			    ESW_FLOW_ATTR_SZ :\
			    NIC_FLOW_ATTR_SZ)

int xsc_tc_num_filters(struct xsc_adapter *priv, unsigned long flags);
int xsc_tc_add_fdb_flow(struct xsc_adapter *priv,
			struct xsc_tc_flow *flow,
			struct netlink_ext_ack *extack);

struct xsc_tc_update_priv {
	struct net_device *fwd_dev;
	bool skb_done;
	bool forward_tx;
};

struct xsc_nic_flow_attr {
	u32 flow_tag;
	u32 hairpin_tirn;
	struct xsc_flow_table *hairpin_ft;
	u32 user_prio;
};

struct xsc_tc_flow_parse_attr;

struct xsc_flow_attr {
	u32 action;
	unsigned long tc_act_cookies[TCA_ACT_MAX_PRIO];
#ifdef CONFIG_XSC_OFFLOAD_COUNTER
	struct xsc_fc *counter;
#endif
	struct xsc_modify_hdr *modify_hdr;
	struct xsc_mod_hdr_handle *mh; /* attached mod header instance */
	struct xsc_mod_hdr_handle *slow_mh; /* attached mod header instance for slow path */
#ifdef CONFIG_XSC_OFFLOAD_CT
	struct xsc_ct_attr ct_attr;
#endif
#ifdef CONFIG_XSC_OFFLOAD_SAMPLE
	struct xsc_sample_attr sample_attr;
#endif
#ifdef CONFIG_XSC_OFFLOAD_METER
	struct xsc_meter_attr meter_attr;
#endif
	struct xsc_tc_flow_parse_attr *parse_attr;
	u32 chain;
	u16 prio;
	u16 tc_act_cookies_count;
	u32 dest_chain;
	struct xsc_flow_table *ft;
	struct xsc_flow_table *dest_ft;
	u8 inner_match_level;
	u8 outer_match_level;
	u8 tun_ip_version;
	int tunnel_id; /* mapped tunnel id */
	u32 flags;
	u32 exe_aso_type;
	struct list_head list;
	struct xsc_post_act_handle *post_act_handle;
	struct xsc_flow_attr *branch_true;
	struct xsc_flow_attr *branch_false;
	struct xsc_flow_attr *jumping_attr;
	struct xsc_flow_handle *act_id_restore_rule;
	struct xsc_esw_flow_attr esw_attr[];
};

enum {
	XSC_ATTR_FLAG_VLAN_HANDLED  = BIT(0),
	XSC_ATTR_FLAG_SLOW_PATH     = BIT(1),
	XSC_ATTR_FLAG_IN_PORT    = BIT(2),
	XSC_ATTR_FLAG_SRC_REWRITE   = BIT(3),
	XSC_ATTR_FLAG_SAMPLE        = BIT(4),
	XSC_ATTR_FLAG_ACCEPT        = BIT(5),
	XSC_ATTR_FLAG_CT            = BIT(6),
	XSC_ATTR_FLAG_TERMINATING   = BIT(7),
	XSC_ATTR_FLAG_MTU           = BIT(8),
};

/* Returns true if any of the flags that require skipping further TC/NF processing are set. */
static inline bool xsc_tc_attr_flags_skip(u32 attr_flags)
{
	return attr_flags & (XSC_ATTR_FLAG_SLOW_PATH | XSC_ATTR_FLAG_ACCEPT);
}

struct xsc_rx_tun_attr {
	u16 decap_vport;
	union {
		__be32 v4;
		struct in6_addr v6;
	} src_ip; /* Valid if decap_vport is not zero */
	union {
		__be32 v4;
		struct in6_addr v6;
	} dst_ip; /* Valid if decap_vport is not zero */
};

#define XSC_TC_TABLE_CHAIN_TAG_BITS 16
#define XSC_TC_TABLE_CHAIN_TAG_MASK GENMASK(XSC_TC_TABLE_CHAIN_TAG_BITS - 1, 0)

#define XSC_TC_MAX_INT_PORT_NUM (32)

struct tunnel_match_key {
	struct flow_dissector_key_control enc_control;
	struct flow_dissector_key_keyid enc_key_id;
	struct flow_dissector_key_ports enc_tp;
	struct flow_dissector_key_ip enc_ip;
	union {
		struct flow_dissector_key_ipv4_addrs enc_ipv4;
		struct flow_dissector_key_ipv6_addrs enc_ipv6;
	};

	int filter_ifindex;
};

struct tunnel_match_enc_opts {
	struct flow_dissector_key_enc_opts key;
	struct flow_dissector_key_enc_opts mask;
};

/* Tunnel_id mapping is TUNNEL_INFO_BITS + ENC_OPTS_BITS.
 * Upper TUNNEL_INFO_BITS for general tunnel info.
 * Lower ENC_OPTS_BITS bits for enc_opts.
 */
#define TUNNEL_INFO_BITS 12
#define TUNNEL_INFO_BITS_MASK GENMASK(TUNNEL_INFO_BITS - 1, 0)
#define ENC_OPTS_BITS 11
#define ENC_OPTS_BITS_MASK GENMASK(ENC_OPTS_BITS - 1, 0)
#define TUNNEL_ID_BITS (TUNNEL_INFO_BITS + ENC_OPTS_BITS)
#define TUNNEL_ID_MASK GENMASK(TUNNEL_ID_BITS - 1, 0)

int xsc_tc_esw_init(struct xsc_rep_uplink_priv *uplink_priv);
void xsc_tc_esw_cleanup(struct xsc_rep_uplink_priv *uplink_priv);

int xsc_tc_ht_init(struct rhashtable *tc_ht);
void xsc_tc_ht_cleanup(struct rhashtable *tc_ht);

int xsc_configure_flower(struct net_device *dev, struct xsc_adapter *priv,
			 struct flow_cls_offload *f, unsigned long flags);
int xsc_delete_flower(struct net_device *dev, struct xsc_adapter *priv,
		      struct flow_cls_offload *f, unsigned long flags);

#ifdef CONFIG_XSC_OFFLOAD_COUNTER
int xsc_stats_flower(struct net_device *dev, struct xsc_adapter *priv,
		     struct flow_cls_offload *f, unsigned long flags);
#endif

#ifdef	CONFIG_XSC_OFFLOAD_OVS
int xsc_tc_fill_action_stats(struct xsc_adapter *priv,
			     struct flow_offload_action *fl_act);
#endif

int xsc_tc_configure_matchall(struct xsc_adapter *priv,
			      struct tc_cls_matchall_offload *f);
int xsc_tc_delete_matchall(struct xsc_adapter *priv,
			   struct tc_cls_matchall_offload *f);

struct xsc_neigh_hash_entry;
struct xsc_encap_entry;

#ifdef CONFIG_XSC_OFFLOAD_TUN
void xsc_tc_encap_flows_add(struct xsc_adapter *priv,
			    struct xsc_encap_entry *e,
			    struct list_head *flow_list);
void xsc_tc_encap_flows_del(struct xsc_adapter *priv,
			    struct xsc_encap_entry *e,
			    struct list_head *flow_list);
bool xsc_encap_take(struct xsc_encap_entry *e);
void xsc_encap_put(struct xsc_adapter *priv, struct xsc_encap_entry *e);
void xsc_take_all_encap_flows(struct xsc_encap_entry *e, struct list_head *flow_list);
void xsc_put_flow_list(struct xsc_adapter *priv, struct list_head *flow_list);
struct xsc_encap_entry *xsc_get_next_init_encap(struct xsc_neigh_hash_entry *nhe,
						struct xsc_encap_entry *e);
#endif

void xsc_tc_update_neigh_used_value(struct xsc_neigh_hash_entry *nhe);

void xsc_tc_reoffload_flows_work(struct work_struct *work);

enum xsc_tc_attr_to_reg {
	MAPPED_OBJ_TO_REG,
	VPORT_TO_REG,
	TUNNEL_TO_REG,
	CTSTATE_TO_REG,
	ZONE_TO_REG,
	ZONE_RESTORE_TO_REG,
	MARK_TO_REG,
	LABELS_TO_REG,
	FTEID_TO_REG,
	NIC_ZONE_RESTORE_TO_REG,
	USER_PRIO_TO_REG,
	HP_OOB_CNT_COLOR_REG,
	HP_OOB_TX_CNT_COLOR_REG,
	PACKET_COLOR_TO_REG,
};

struct xsc_tc_attr_to_reg_mapping {
	int mfield; /* rewrite field */
	int moffset; /* bit offset of mfield */
	int mlen; /* bits to rewrite/match */
	int soffset; /* byte offset of spec for match */
};

extern struct xsc_tc_attr_to_reg_mapping xsc_tc_attr_to_reg_mappings[];

#define XSC_REG_MAPPING_MOFFSET(reg_id) (xsc_tc_attr_to_reg_mappings[reg_id].moffset)
#define XSC_REG_MAPPING_MBITS(reg_id) (xsc_tc_attr_to_reg_mappings[reg_id].mlen)
#define XSC_REG_MAPPING_MASK(reg_id) (GENMASK(xsc_tc_attr_to_reg_mappings[reg_id].mlen - 1, 0))

bool same_port_devs(struct xsc_adapter *priv, struct xsc_adapter *peer_priv);
bool xsc_is_valid_eswitch_fwd_dev(struct xsc_adapter *priv,
				  struct net_device *out_dev);

int xsc_tc_match_to_reg_set(struct xsc_core_device *xdev,
			    struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
			    enum xsc_flow_namespace_type ns,
			    enum xsc_tc_attr_to_reg type,
			    u32 data);

void xsc_tc_match_to_reg_mod_hdr_change(struct xsc_core_device *xdev,
					struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
					enum xsc_tc_attr_to_reg type,
					int act_id, u32 data);

void xsc_tc_match_to_reg_match(struct xsc_flow_spec *spec,
			       enum xsc_tc_attr_to_reg type,
			       u32 data, u32 mask);

void xsc_tc_match_to_reg_get_match(struct xsc_flow_spec *spec,
				   enum xsc_tc_attr_to_reg type,
				   u32 *data, u32 *mask);

int xsc_tc_match_to_reg_set_and_get_id(struct xsc_core_device *xdev,
				       struct xsc_tc_mod_hdr_acts *mod_hdr_acts,
				       enum xsc_flow_namespace_type ns,
				       enum xsc_tc_attr_to_reg type,
				       u32 data);

int xsc_tc_attach_mod_hdr(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			  struct xsc_flow_attr *attr);

void xsc_tc_detach_mod_hdr(struct xsc_adapter *priv, struct xsc_tc_flow *flow,
			   struct xsc_flow_attr *attr);

void xsc_tc_set_ethertype(struct xsc_core_device *xdev,
			  struct flow_match_basic *match, bool outer,
			  void *headers_c, void *headers_v, u64 *attr);

int xsc_tc_nic_init(struct xsc_adapter *priv);
void xsc_tc_nic_cleanup(struct xsc_adapter *priv);

struct xsc_flow_handle *
xsc_tc_rule_insert(struct xsc_adapter *priv,
		   struct xsc_flow_spec *spec,
		   struct xsc_flow_attr *attr);
void
xsc_tc_rule_delete(struct xsc_adapter *priv,
		   struct xsc_flow_handle *rule,
		   struct xsc_flow_attr *attr);

#ifdef CONFIG_XSC_OFFLOAD_OVS
int xsc_set_fwd_to_int_port_actions(struct xsc_adapter *priv,
				    struct xsc_flow_attr *attr,
				    int ifindex,
				    enum xsc_tc_int_port_type type,
				    u32 *action,
				    int out_index);
#endif
int xsc_setup_tc_block_cb(enum tc_setup_type type, void *type_data,
			  void *cb_priv);

struct xsc_flow_attr *xsc_alloc_flow_attr(enum xsc_flow_namespace_type type);

void unready_flow_del(struct xsc_tc_flow *flow);

#ifdef CONFIG_XSC_OFFLOAD_CT
int xsc_tc_action_miss_mapping_get(struct xsc_adapter *priv, struct xsc_flow_attr *attr,
				   u64 act_miss_cookie, u32 *act_miss_mapping);
void xsc_tc_action_miss_mapping_put(struct xsc_adapter *priv, struct xsc_flow_attr *attr,
				    u32 act_miss_mapping);
#endif

#endif /* __TC_FLOW_H__ */
