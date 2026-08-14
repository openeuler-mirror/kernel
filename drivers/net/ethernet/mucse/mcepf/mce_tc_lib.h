/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_TC_LIB_H_
#define _MCE_TC_LIB_H_
#include "mce_type.h"

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_FLWR_FIELD_DST_MAC BIT(0)
#define MCE_TC_FLWR_FIELD_SRC_MAC BIT(1)
#define MCE_TC_FLWR_FIELD_VLAN BIT(2)
#define MCE_TC_FLWR_FIELD_DEST_IPV4 BIT(3)
#define MCE_TC_FLWR_FIELD_SRC_IPV4 BIT(4)
#define MCE_TC_FLWR_FIELD_DEST_IPV6 BIT(5)
#define MCE_TC_FLWR_FIELD_SRC_IPV6 BIT(6)
#define MCE_TC_FLWR_FIELD_DEST_L4_PORT BIT(7)
#define MCE_TC_FLWR_FIELD_SRC_L4_PORT BIT(8)
#define MCE_TC_FLWR_FIELD_TENANT_ID BIT(9)
#define MCE_TC_FLWR_FIELD_ENC_DEST_IPV4 BIT(10)
#define MCE_TC_FLWR_FIELD_ENC_SRC_IPV4 BIT(11)
#define MCE_TC_FLWR_FIELD_ENC_DEST_IPV6 BIT(12)
#define MCE_TC_FLWR_FIELD_ENC_SRC_IPV6 BIT(13)
#define MCE_TC_FLWR_FIELD_ENC_DEST_L4_PORT BIT(14)
#define MCE_TC_FLWR_FIELD_ENC_SRC_L4_PORT BIT(15)
#define MCE_TC_FLWR_FIELD_ENC_DST_MAC BIT(16)
#define MCE_TC_FLWR_FIELD_ETH_TYPE_ID BIT(17)
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_FLWR_FIELD_IP_TOS BIT(19)
#define MCE_TC_FLWR_FIELD_IP_TTL BIT(20)
#endif /* CONFIG_NET_CLS_FLOWER */
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_FLWR_FIELD_ENC_IP_TOS BIT(21)
#define MCE_TC_FLWR_FIELD_ENC_IP_TTL BIT(22)
#endif /* CONFIG_NET_CLS_FLOWER */
#define MCE_TC_FLWR_FIELD_ZERO_DST_MAC BIT(23)
#define MCE_TC_FLWR_FIELD_ZERO_ENC_DST_MAC BIT(24)
#define MCE_TC_FLWR_FIELD_CVLAN BIT(25)
#define MCE_TC_FLWR_FIELD_VLAN_PRIO BIT(27)
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_FLWR_FIELD_CVLAN_PRIO BIT(28)
#endif /* CONFIG_NET_CLS_FLOWER */
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_TC_FLWR_FIELD_VLAN_TPID BIT(29)
#endif /* CONFIG_NET_CLS_FLOWER */
#define MCE_TC_FLWR_FIELD_FLAGS_IS_FRAGMENT BIT(30)
#define MCE_TC_FLWR_FIELD_IPSEC_SPI BIT(31)

/* TC flower supported filter match */
#define MCE_TC_FLWR_FLTR_FLAGS_DST_MAC MCE_TC_FLWR_FIELD_DST_MAC
#define MCE_TC_FLWR_FLTR_FLAGS_VLAN MCE_TC_FLWR_FIELD_VLAN
#define MCE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN \
	(MCE_TC_FLWR_FIELD_DST_MAC | MCE_TC_FLWR_FIELD_VLAN)
#define MCE_TC_FLWR_FLTR_FLAGS_IPV4_DST_PORT \
	(MCE_TC_FLWR_FIELD_DEST_IPV4 | MCE_TC_FLWR_FIELD_DEST_L4_PORT)
#define MCE_TC_FLWR_FLTR_FLAGS_IPV4_SRC_PORT \
	(MCE_TC_FLWR_FIELD_DEST_IPV4 | MCE_TC_FLWR_FIELD_SRC_L4_PORT)
#define MCE_TC_FLWR_FLTR_FLAGS_IPV6_DST_PORT \
	(MCE_TC_FLWR_FIELD_DEST_IPV6 | MCE_TC_FLWR_FIELD_DEST_L4_PORT)
#define MCE_TC_FLWR_FLTR_FLAGS_IPV6_SRC_PORT \
	(MCE_TC_FLWR_FIELD_DEST_IPV6 | MCE_TC_FLWR_FIELD_SRC_L4_PORT)

#define MCE_TC_FLOWER_MASK_32 0xFFFFFFFF
#define MCE_TC_FLOWER_MASK_16 0xFFFF
#define MCE_TC_FLOWER_VNI_MAX 0xFFFFFFU

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
#define MCE_IPV6_HDR_TC_OFFSET 20
#define MCE_IPV6_HDR_TC_MASK GENMASK(27, 20)
#endif /* CONFIG_NET_CLS_FLOWER */

#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
struct mce_indr_block_priv {
	struct net_device *netdev;
	struct mce_netdev_priv *np;
	struct list_head list;
};
#endif /* CONFIG_NET_CLS_FLOWER */

struct mce_tc_flower_action {
	/* forward action specific params */
	union {
		struct {
			u32 tc_class; /* forward to hw_tc */
			u32 rsvd;
		} tc;
		struct {
			u32 queue; /* forward to queue */
			/* to add filter in HW, it needs absolute queue number
			 * in global space of queues (between 0...N)
			 */
			u32 hw_queue;
		} q;
	} fwd;
	enum mce_sw_fwd_act_type fltr_act;
	bool pop_vlan;
};

struct mce_tc_vlan_hdr {
	__be16 vlan_id; /* Only last 12 bits valid */
	__be16 vlan_prio; /* Only first 3 bits valid (valid values: 0..7) */
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
	__be16 vlan_tpid;
#endif /* CONFIG_NET_CLS_FLOWER */
};

struct mce_tc_pppoe_hdr {
	__be16 session_id;
	__be16 ppp_proto;
};

struct mce_tc_l2_hdr {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 n_proto; /* Ethernet Protocol */
};

struct mce_tc_l3_hdr {
	u8 ip_proto; /* IPPROTO value */
	union {
		struct {
			struct in_addr dst_ip;
			struct in_addr src_ip;
		} v4;
		struct {
			struct in6_addr dst_ip6;
			struct in6_addr src_ip6;
		} v6;
	} ip;
#define dst_ipv6 ip.v6.dst_ip6.s6_addr32
#define dst_ipv6_addr ip.v6.dst_ip6.s6_addr
#define src_ipv6 ip.v6.src_ip6.s6_addr32
#define src_ipv6_addr ip.v6.src_ip6.s6_addr
#define dst_ipv4 ip.v4.dst_ip.s_addr
#define src_ipv4 ip.v4.src_ip.s_addr

	u8 tos;
	u8 ttl;
};

struct mce_tc_ipsec_hdr {
	__be32 spi;
};

struct mce_tc_l4_hdr {
	__be16 dst_port;
	__be16 src_port;
};

struct mce_tc_flower_lyr_2_4_hdrs {
	/* L2 layer fields with their mask */
	struct mce_tc_l2_hdr l2_key;
	struct mce_tc_l2_hdr l2_mask;
	struct mce_tc_vlan_hdr vlan_hdr;
	struct mce_tc_vlan_hdr cvlan_hdr;
	struct mce_tc_pppoe_hdr pppoe_hdr;
	struct mce_tc_ipsec_hdr ipsec_hdr;
	struct mce_tc_ipsec_hdr ipsec_mask;
	/* L3 (IPv4[6]) layer fields with their mask */
	struct mce_tc_l3_hdr l3_key;
	struct mce_tc_l3_hdr l3_mask;

	/* L4 layer fields with their mask */
	struct mce_tc_l4_hdr l4_key;
	struct mce_tc_l4_hdr l4_mask;
};

enum mce_eswitch_fltr_direction {
	MCE_ESWITCH_FLTR_INGRESS,
	MCE_ESWITCH_FLTR_EGRESS,
};

enum mce_fdir_rule_owner {
	MCE_FDIR_RULE_OWNER_TC,
	MCE_FDIR_RULE_OWNER_ARFS,
};

struct mce_tc_flower_fltr {
	struct hlist_node tc_flower_node;

	/* cookie becomes filter_rule_id if rule is added successfully */
	unsigned long cookie;

	/* add_adv_rule returns information like recipe ID, rule_id. Store
	 * those values since they are needed to remove advanced rule
	 */
	int q_index;
	u32 fltr_id;
	/* VSI handle of the destination VSI (it could be main PF VSI, CHNL_VSI,
	 * VF VSI)
	 */
	u16 dest_vsi_handle;
	/* ptr to destination VSI */
	struct mce_vsi *dest_vsi;
	/* direction of fltr for eswitch use case */
	enum mce_eswitch_fltr_direction direction;

	/* Parsed TC flower configuration params */
	struct mce_tc_flower_lyr_2_4_hdrs outer_headers;
	struct mce_tc_flower_lyr_2_4_hdrs inner_headers;
	struct mce_vsi *src_vsi;
	__be32 tenant_id;
	u64 flags;
#define MCE_TC_FLWR_TNL_TYPE_NONE 0xff
	u8 tunnel_type;
	u8 tunnel_sw_type;
	bool ipsec_en;
	bool parsed_inner;
	enum mce_flow_module f_module;
	enum mce_fdir_rule_owner fdir_owner;
	struct mce_tc_flower_action action;

	/* cache ptr which is used wherever needed to communicate netlink
	 * messages
	 */
	struct netlink_ext_ack *extack;
	struct mce_fdir_filter *filter;
	struct mce_eswitch_filter *efilter;
};

int mce_add_tc_flower_adv_fltr(struct mce_vsi *vsi,
			       struct mce_tc_flower_fltr *tc_fltr);

struct mce_vsi *mce_locate_vsi_using_queue(struct mce_vsi *vsi,
					   int queue);
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)
int mce_tc_tun_get_type(struct net_device *tunnel_dev,
			struct flow_rule *rule,
			struct mce_tc_flower_fltr *fltr);
#endif /* CONFIG_NET_CLS_FLOWER */
int mce_add_cls_flower(struct net_device *netdev, struct mce_vsi *vsi,
		       struct flow_cls_offload *cls_flower);
int mce_del_cls_flower(struct mce_vsi *vsi,
		       struct flow_cls_offload *cls_flower);
int mce_fdir_flow_query_tc_flower_fltr(struct mce_pf *pf);
void *mce_get_engine_handle(struct mce_pf *pf, enum mce_flow_module type);
int mce_init_flow_engine(struct mce_pf *pf, enum mce_flow_module module);
void mce_deinit_flow_engine(struct mce_pf *pf, enum mce_flow_module module);
#endif /* CONFIG_NET_CLS_FLOWER */
#endif /* _MCE_TC_LIB_H_ */
