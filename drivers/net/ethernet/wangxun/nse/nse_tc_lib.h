/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_TC_LIB_H_
#define _NSE_TC_LIB_H_

#define NSE_TC_FLOWER_MASK_32	0xFFFFFFFF
#define NSE_TC_FLOWER_MASK_16	0xFFFF
#define NSE_TC_FLOWER_MASK_8	0xFF
#define NSE_TC_FLOWER_VNI_MAX	0xFFFFFFU
#define NSE_VLAN_PRIO_MASK		0x7

#define NSE_MAX_SET_MD_NUM	2

#define NSE_IPV6_HDR_TC_OFFSET 20
#define NSE_IPV6_HDR_TC_MASK GENMASK(27, 20)

struct nse_indr_block_priv {
	struct net_device *netdev;
	struct nse_netdev_priv *np;
	struct list_head list;
};

struct nse_tc_vlan_hdr {
	__be16 vlan_id; /* Only last 12 bits valid */
	u16 vlan_prio; /* Only last 3 bits valid (valid values: 0..7) */
};

struct nse_tc_pppoe_hdr {
	__be16 session_id;
	__be16 ppp_proto;
};

struct nse_tc_l2_hdr {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 n_proto;    /* Ethernet Protocol */
};

struct nse_tc_l3_hdr {
	u8 ip_proto;    /* IPPROTO value */
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
#define dst_ipv6	ip.v6.dst_ip6.s6_addr32
#define dst_ipv6_addr	ip.v6.dst_ip6.s6_addr
#define src_ipv6	ip.v6.src_ip6.s6_addr32
#define src_ipv6_addr	ip.v6.src_ip6.s6_addr
#define dst_ipv4	ip.v4.dst_ip.s_addr
#define src_ipv4	ip.v4.src_ip.s_addr

	u8 tos;
	u8 ttl;
};

struct nse_tc_l4_hdr {
	__be16 dst_port;
	__be16 src_port;
	__be16 tcp_flags;
};

struct nse_tc_flower_lyr_2_4_hdrs {
	/* L2 layer fields with their mask */
	struct nse_tc_l2_hdr l2_key;
	struct nse_tc_l2_hdr l2_mask;
	struct nse_tc_vlan_hdr vlan_hdr; /*no mask for vlan match*/
	struct nse_tc_vlan_hdr cvlan_hdr; /*no mask for vlan match*/
	struct nse_tc_pppoe_hdr pppoe_hdr;

	/* L3 (IPv4[6]) layer fields with their mask */
	struct nse_tc_l3_hdr l3_key;
	struct nse_tc_l3_hdr l3_mask;

	/* L4 layer fields with their mask */
	struct nse_tc_l4_hdr l4_key;
	struct nse_tc_l4_hdr l4_mask;
};

struct nse_total_vxlan_v4_header {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 n_proto;
	struct iphdr ip_hdr;
	struct udphdr udp_hdr;
	struct vxlanhdr vxlan_hdr;
} __packed;

struct nse_total_vxlan_v6_header {
	u8 dst_mac[ETH_ALEN];
	u8 src_mac[ETH_ALEN];
	__be16 n_proto;
	struct ipv6hdr ipv6_hdr;
	struct udphdr udp_hdr;
	struct vxlanhdr vxlan_hdr;
} __packed;

struct nse_tc_tun_route_attr {
	struct net_device *out_dev;
	struct net_device *route_dev;
	union {
		struct flowi4 fl4;
		struct flowi6 fl6;
	} fl;
	struct neighbour *n;
	u8 ttl;
};

struct pedit_headers {
	struct ethhdr  eth;
	struct vlan_hdr vlan;
	struct iphdr   ip4;
	struct ipv6hdr ip6;
	struct tcphdr  tcp;
	struct udphdr  udp;
};

struct nse_pedit_headers {
	struct pedit_headers	vals;
	struct pedit_headers	masks;
	u32			pedits;
};

#define NSE_PEDIT_L2_DMAC_MAX_OFFSET 6
#define NSE_PEDIT_L2_SMAC_MAX_OFFSET 12

#define NSE_TC_FLWR_LARGE_ACTION_INVALID		NSE_NODE_STATE_ID_INVALID
#define NSE_TC_FLWR_VSI_LIST_ID_INVALID		NSE_VSI_LIST_ID_INVALID

struct nse_tc_flower_action {
	/*common info*/
	u16 large_act_id; /*same as note state id*/
	struct nse_node_state node_state;
	struct nse_sw_task_list *task_list;
	struct nse_sw_du_data *du_data;
	u32 flags;
#define NSE_TC_FLWR_ACTION_ALLOW			BIT(0)
#define NSE_TC_FLWR_ACTION_DROP				BIT(1)
#define NSE_TC_FLWR_ACTION_TO_LAN			BIT(2)
#define NSE_TC_FLWR_ACTION_FWD_VSI			BIT(3)
#define NSE_TC_FLWR_ACTION_FWD_VSI_LIST		BIT(4)
#define NSE_TC_FLWR_ACTION_COUNT			BIT(5)
#define NSE_TC_FLWR_ACTION_REWRITE			BIT(6)
#define NSE_TC_FLWR_ACTION_VLAN_PUSH		BIT(7)
#define NSE_TC_FLWR_ACTION_VLAN_POP			BIT(8)
#define NSE_TC_FLWR_ACTION_DECAP			BIT(9)
#define NSE_TC_FLWR_ACTION_SINGLE_ENCAP		BIT(10) /*Single Encap flag*/
#define NSE_TC_FLWR_ACTION_DUP				BIT(11)
#define NSE_TC_FLWR_ACTION_METER			BIT(12)
#define NSE_TC_FLWR_ACTION_GOTO_CHAIN		BIT(13)
#define NSE_TC_FLWR_ACTION_SFLOW			BIT(14)
#define NSE_TC_FLWR_ACTION_CT				BIT(15) /* tc flower ct action*/
#define NSE_TC_FLWR_ACTION_SET_MD			BIT(16) /* set generic md */

	/*redirect/mirrored info*/
	enum nse_sw_fwd_act_type fltr_act;
	u8 lan_en; /*indicate there is a uplink dest vsi*/
	u16 dest_cnt;
	struct {
		struct nse_vsi *dest_vsi;
		u32 flags;
#define NSE_TC_FLWR_ACTION_DEST_ENCAP_VLD	BIT(0)
		struct ip_tunnel_info *tun_info;
		struct net_device *target_dev;
	} dests[NSE_MAX_FLOW_FWD_DEST];

	/* sflow*/
	struct nse_sw_sflow_info sflow_info;
	struct nse_vsi *sflow_dest_vsi;
	struct nse_sw_sflow *sflow;

	/* goto chain*/
	u8 dest_chain;

	/* ct */
	u16 zone;
	u16 ct_action;
	struct nf_flowtable *nf_ft;

	/* metadata to set*/
	u8 md_num;
	u16 md_value[NSE_MAX_SET_MD_NUM];
	u8 dest_md_id[NSE_MAX_SET_MD_NUM];

	/*meter info*/
	struct nse_sw_meter_param meter_param;
	struct nse_sw_meter *meter;

	/*push vlan info*/
	__be16	vlan_proto;
	u16	vlan_vid;
	u8	vlan_prio;

	/*tunnel encap info*/
	u16 encap_cnt;
	struct nse_sw_encap_entry *encap_entry; /*single encap*/
	struct nse_sw_m_encap_entry *m_encap_entry; /*multi encap*/
	struct nse_sw_encap_item encaps[NSE_MAX_FLOW_ENCAP_CNT]; /*for neigh update*/

	/*vsi list id info*/
	u16 vsi_list_id;
	struct nse_vsi_list_map_info *vsi_list_info;

	/*dup info*/
	u16 copy_num;

	/*count info*/
	struct nse_sw_counter_pair *counter_p;

	/*mangle info*/
	struct nse_pedit_headers hdrs;
	u32 rw_flag;
#define NSE_SW_REWRITE_L2_DMAC				BIT(0)
#define NSE_SW_REWRITE_L2_SMAC				BIT(1)
#define NSE_SW_REWRITE_L3_TOS_V4			BIT(2)
#define NSE_SW_REWRITE_L3_TTL_V4			BIT(3)
#define NSE_SW_REWRITE_L3_DIP_V4			BIT(4)
#define NSE_SW_REWRITE_L3_SIP_V4			BIT(5)
#define NSE_SW_REWRITE_L3_HLIMIT_V6		BIT(6)
#define NSE_SW_REWRITE_L3_DIP_V6			BIT(7)
#define NSE_SW_REWRITE_L3_SIP_V6			BIT(8)
#define NSE_SW_REWRITE_L4_DPORT				BIT(9)
#define NSE_SW_REWRITE_L4_SPORT				BIT(10)
#define NSE_SW_REWRITE_L2_VLAN_ID			BIT(11)
#define NSE_SW_REWRITE_L3_TOS_V6			BIT(12)
};

struct nse_ipv6hdr_tos {
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u8		priority_hi:4,
				version:4;
	__u8		flow_lbl_hi:4,
				priority_lo:4;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u8		version:4,
				priority_hi:4;
	__u8		priority_lo:4,
				flow_lbl_hi:4;
#else
#error	"Please fix <asm/byteorder.h>"
#endif
	__be16		flow_lbl_lo;
};

struct nse_ipv6_hop_limit {
	__be16 payload_len;
	u8 nexthdr;
	u8 hop_limit;
};

struct nse_ipv4_ttl_word {
	__u8	ttl;
	__u8	protocol;
	__sum16	check;
};

struct nse_tc_ct_flow;

union nse_flow_attr {
	struct {
		u32 ipv4:1; /*for modify ttl/tos action, not used in kernel*/
		u32 ipv6:1;
		u32 tcp:1;
		u32 udp:1;
		u32 enc_ipv4_match: 1; /*for ttl/tos match*/
		u32 ipv4_match: 1;
		u32 enc_ipv6_match: 1;
		u32 ipv6_match: 1;
		u32 reserved:24;
	};
	u32 attr;
};

struct nse_tc_flower_fltr {
	struct hlist_node tc_flower_node;

	refcount_t ref_cnt;
	unsigned long cookie;
	u16 lut_id;
	u16 node_id;

	/* for conntrack flow */
	struct nse_tc_ct_flow *ct_flow;

	/* for debug fs cmd temporily
	 *  false: from debugfs tool, dest vsi can be 0
	 *  true:  from tc_flower cmd, vsi 0 can't be dest vsi, vsi 0 means toLan.
	 */
	bool tc_flower;

	/* source VSI (it could be Uplink VSI, VF VSI) */
	struct nse_vsi *src_vsi;

	/* src chain id where this tc flower filtr located */
	u8 chain_id;

	/* Parsed action configuration params */
	struct nse_tc_flower_action	action;

	/* Parsed match configuration params */
	struct nse_tc_flower_lyr_2_4_hdrs outer_headers;
	struct nse_tc_flower_lyr_2_4_hdrs inner_headers;
	u8 tunnel_type;
#define NSE_TC_FLWR_TNL_TYPE_NONE        0xff
	__be32 tenant_id;
	union nse_flow_attr flow_attr;

	/* fte_id for match of post ct entry */
	u16 fte_id;
	u16 zone;
	u16 ct_state;
	u16 ct_state_mask;
	u32 flags;
#define NSE_TC_FLWR_FIELD_DST_MAC		BIT(0)
#define NSE_TC_FLWR_FIELD_SRC_MAC		BIT(1)
#define NSE_TC_FLWR_FIELD_VLAN			BIT(2)
#define NSE_TC_FLWR_FIELD_DEST_IPV4		BIT(3)
#define NSE_TC_FLWR_FIELD_SRC_IPV4		BIT(4)
#define NSE_TC_FLWR_FIELD_DEST_IPV6		BIT(5)
#define NSE_TC_FLWR_FIELD_SRC_IPV6		BIT(6)
#define NSE_TC_FLWR_FIELD_DEST_L4_PORT		BIT(7)
#define NSE_TC_FLWR_FIELD_SRC_L4_PORT		BIT(8)
#define NSE_TC_FLWR_FIELD_TENANT_ID		BIT(9)
#define NSE_TC_FLWR_FIELD_ENC_DEST_IPV4		BIT(10)
#define NSE_TC_FLWR_FIELD_ENC_SRC_IPV4		BIT(11)
#define NSE_TC_FLWR_FIELD_ENC_DEST_IPV6		BIT(12)
#define NSE_TC_FLWR_FIELD_ENC_SRC_IPV6		BIT(13)
#define NSE_TC_FLWR_FIELD_ENC_DEST_L4_PORT	BIT(14)
#define NSE_TC_FLWR_FIELD_ENC_SRC_L4_PORT	BIT(15)
#define NSE_TC_FLWR_FIELD_ENC_DST_MAC		BIT(16)
#define NSE_TC_FLWR_FIELD_ETH_TYPE		BIT(17)
#define NSE_TC_FLWR_FIELD_ENC_OPTS		BIT(18)
#define NSE_TC_FLWR_FIELD_IP_TOS		BIT(19)
#define NSE_TC_FLWR_FIELD_IP_TTL		BIT(20)
#define NSE_TC_FLWR_FIELD_ENC_IP_TOS		BIT(21)
#define NSE_TC_FLWR_FIELD_ENC_IP_TTL		BIT(22)
#define NSE_TC_FLWR_FIELD_PPPOE_SESSID		BIT(23)
#define NSE_TC_FLWR_FIELD_PPP_PROTO		BIT(24)
#define NSE_TC_FLWR_FIELD_CVLAN			BIT(25)
#define NSE_TC_FLWR_FIELD_CT_STATE		BIT(26)
#define NSE_TC_FLWR_FIELD_FTE_ID		BIT(27)
#define NSE_TC_FLWR_FIELD_IN_PORT		BIT(28)
#define NSE_TC_FLWR_FIELD_ZONE_ID		BIT(29)
#define NSE_TC_FLWR_FIELD_TCP_FLAGS		BIT(30)

#define NSE_TC_FLWR_FLTR_FLAGS_DST_MAC		NSE_TC_FLWR_FIELD_DST_MAC
#define NSE_TC_FLWR_FLTR_FLAGS_VLAN		NSE_TC_FLWR_FIELD_VLAN
#define NSE_TC_FLWR_FLTR_FLAGS_DST_MAC_VLAN	(NSE_TC_FLWR_FIELD_DST_MAC | \
							 NSE_TC_FLWR_FIELD_VLAN)
#define NSE_TC_FLWR_FLTR_FLAGS_IPV4_DST_PORT	(NSE_TC_FLWR_FIELD_DEST_IPV4 | \
							 NSE_TC_FLWR_FIELD_DEST_L4_PORT)
#define NSE_TC_FLWR_FLTR_FLAGS_IPV4_SRC_PORT	(NSE_TC_FLWR_FIELD_DEST_IPV4 | \
							 NSE_TC_FLWR_FIELD_SRC_L4_PORT)
#define NSE_TC_FLWR_FLTR_FLAGS_IPV6_DST_PORT	(NSE_TC_FLWR_FIELD_DEST_IPV6 | \
							 NSE_TC_FLWR_FIELD_DEST_L4_PORT)
#define NSE_TC_FLWR_FLTR_FLAGS_IPV6_SRC_PORT	(NSE_TC_FLWR_FIELD_DEST_IPV6 | \
							 NSE_TC_FLWR_FIELD_SRC_L4_PORT)

	struct netlink_ext_ack *extack;
};

struct nse_tc_ct_flow {
	struct nse_tc_flower_fltr *pre_ct;
	struct nse_tc_flower_fltr *post_ct;
	struct nse_ct_ft *ft;
	u16 fte_id;
};

int
nse_tc_tun_get_type(struct net_device *tunnel_dev,
		    struct flow_rule *rule);

int
nse_add_cls_flower(struct net_device *netdev, struct nse_vsi *vsi,
		   struct flow_cls_offload *cls_flower);

int
nse_add_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act);

int
nse_del_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act);

int
nse_get_stats_fl_action(struct nse_netdev_priv *np,
			 struct flow_offload_action *fl_act);

int
nse_del_cls_flower(struct nse_vsi *vsi, struct flow_cls_offload *cls_flower);

int
nse_stats_cls_flower(struct nse_vsi *vsi, struct flow_cls_offload *cls_flower);

void nse_replay_tc_fltrs(struct nse_pf *pf);

void nse_cleanup_tc_fltrs(struct nse_pf *pf);

int
nse_eswitch_add_tc_fltr(struct nse_vsi *vsi,
		struct nse_tc_flower_fltr *fltr);

int
nse_tc_setup_pedit_action(struct net_device *filter_dev, struct nse_tc_flower_fltr *fltr,
			     const struct flow_action_entry *act,
			     struct nse_pedit_headers *hdrs);

int
nse_tc_add_large_action(struct nse_vsi *vsi,
			struct nse_tc_flower_fltr *fltr);

void nse_tc_fltr_init(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr);

int
nse_tc_set_ipv4(struct flow_match_ipv4_addrs *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap);

int
nse_tc_set_ipv6(struct flow_match_ipv6_addrs *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap);

int
nse_tc_set_port(struct flow_match_ports *match,
		struct nse_tc_flower_fltr *fltr,
		struct nse_tc_flower_lyr_2_4_hdrs *headers, bool is_encap);

void nse_fc_query_cached(struct nse_sw_counter_pair *counter_p,
			  u64 *o_bytes, u64 *o_packets, u64 *o_lastuse);

int
nse_eswitch_set_mode(struct nse_pf *pf, u32 mode);

void nse_del_tc_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr);

void nse_put_tc_fltr(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr);

void nse_get_tc_fltr(struct nse_tc_flower_fltr *fltr);

int nse_tc_fltr_enable_slowpath(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr);

int nse_tc_fltr_disable_slowpath(struct nse_vsi *vsi, struct nse_tc_flower_fltr *fltr);

bool nse_tc_fltr_all_encaps_valid(struct nse_tc_flower_fltr *fltr);

void
nse_tc_fltr_detach_encap(struct nse_sw_encap_item *fltr_encap_item);

#endif

