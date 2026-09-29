/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2024-2026 Mucse Corporation. */

#ifndef _MCE_PATTERN_H_
#define _MCE_PATTERN_H_

/* support pattern proto */
#define MCE_PATTERN_MAC BIT_ULL(0)
#define MCE_PATTERN_IPV4 BIT_ULL(1)
#define MCE_PATTERN_IPV6 BIT_ULL(2)
#define MCE_PATTERN_UDP BIT_ULL(3)
#define MCE_PATTERN_TCP BIT_ULL(4)
#define MCE_PATTERN_SCTP BIT_ULL(5)
#define MCE_PATTERN_ESP BIT_ULL(6)
#define MCE_PATTERN_GRE BIT_ULL(7)
#define MCE_PATTERN_NVGRE BIT_ULL(8)
#define MCE_PATTERN_VXLAN BIT_ULL(9)
#define MCE_PATTERN_GTP_C BIT_ULL(10)
#define MCE_PATTERN_GTP_U BIT_BIT64(11)

/* support pattern options */
#define MCE_OPT_SMAC BIT_ULL(63)
#define MCE_OPT_DMAC BIT_ULL(62)
#define MCE_OPT_ETHTYPE BIT_ULL(61)
#define MCE_OPT_IPV4_SIP BIT_ULL(60)
#define MCE_OPT_IPV4_DIP BIT_ULL(59)
#define MCE_OPT_IPV4_DSCP BIT_ULL(58)
#define MCE_OPT_IPV4_FRAG BIT_ULL(57)
#define MCE_OPT_IPV6_SIP BIT_ULL(56)
#define MCE_OPT_IPV6_DIP BIT_ULL(55)
#define MCE_OPT_IPV6_DSCP BIT_ULL(54)
#define MCE_OPT_IPV6_FRAG BIT_ULL(53)
#define MCE_OPT_L4_PROTO BIT_ULL(52)
#define MCE_OPT_UDP_SPORT BIT_ULL(51)
#define MCE_OPT_UDP_DPORT BIT_ULL(50)
#define MCE_OPT_TCP_SPORT BIT_ULL(49)
#define MCE_OPT_TCP_DPORT BIT_ULL(48)
#define MCE_OPT_TCP_SYNC BIT_ULL(47)
#define MCE_OPT_SCTP_SPORT BIT_ULL(46)
#define MCE_OPT_SCTP_DPORT BIT_ULL(45)
#define MCE_OPT_ESP_SPI BIT_ULL(44)
/* Only valid gre protocol type is 0x6558 */
#define MCE_OPT_NVGRE_TNI BIT_ULL(42)
#define MCE_OPT_VXLAN_VNI BIT_ULL(41)
#define MCE_OPT_GTP_C_TEID BIT_ULL(40)
#define MCE_OPT_GTP_U_TEID BIT_ULL(39)
/* only support for tunnel packet select out options */
#define MCE_OPT_OUT_IPV4_SIP BIT_ULL(38)
#define MCE_OPT_OUT_IPV4_DIP BIT_ULL(37)
#define MCE_OPT_OUT_IPV6_SIP BIT_ULL(36)
#define MCE_OPT_OUT_IPV6_DIP BIT_ULL(35)
#define MCE_OPT_OUT_L4_SPORT BIT_ULL(34)
#define MCE_OPT_OUT_L4_DPORT BIT_ULL(33)
#define MCE_OPT_VLAN_VID BIT_ULL(32)
#define MCE_OPT_L4_SPORT \
	(MCE_OPT_UDP_SPORT | MCE_OPT_TCP_SPORT | MCE_OPT_SCTP_SPORT)
#define MCE_OPT_L4_DPORT \
	(MCE_OPT_UDP_DPORT | MCE_OPT_TCP_DPORT | MCE_OPT_SCTP_DPORT)
#define MCE_OPT_OUT_IP_PORT                              \
	(MCE_OPT_OUT_IPV4_SIP | MCE_OPT_OUT_IPV4_DIP | \
	 MCE_OPT_OUT_IPV6_SIP | MCE_OPT_OUT_IPV6_DIP | \
	 MCE_OPT_OUT_L4_SPORT | MCE_OPT_OUT_L4_DPORT)
#define MCE_OPT_IN_IP_PORT                                        \
	(MCE_OPT_IPV4_SIP | MCE_OPT_IPV4_DIP | MCE_OPT_IPV6_SIP | \
	 MCE_OPT_IPV6_DIP | MCE_OPT_L4_SPORT | MCE_OPT_L4_DPORT)
#define MCE_OPT_SRC_IP_PORT                                               \
	(MCE_OPT_OUT_IPV4_SIP | MCE_OPT_IPV4_SIP | MCE_OPT_OUT_IPV6_SIP | \
	 MCE_OPT_IPV6_SIP | MCE_OPT_OUT_L4_SPORT | MCE_OPT_L4_SPORT)
#define MCE_OPT_GENEVE_VNI BIT_ULL(31)
#define MCE_OPT_SCTP_VTAG BIT_ULL(30)
#define MCE_OPT_OUT_SCTP_VTAG BIT_ULL(29)
#define MCE_OPT_S_VPORT_ID BIT_ULL(28)

#define MCE_TUNNEL_OPT                                                \
	(MCE_OPT_GENEVE_VNI | MCE_OPT_VXLAN_VNI | MCE_OPT_NVGRE_TNI | \
	 MCE_OPT_GTP_C_TEID | MCE_OPT_GTP_U_TEID)
#define MCE_TUNNEL_VLAN_OPT_MASK (MCE_TUNNEL_OPT | MCE_OPT_VLAN_VID)
/* hw packet predecode compose code */
#define MCE_PTYPE_UNKNOWN (0b000000)
#define MCE_PTYPE_L2_ONLY (0b000001)
#define MCE_PTYPE_TUN_INNER_L2_ONLY (0b000010)
#define MCE_PTYPE_TUN_OUTER_L2_ONLY (0b000011)
#define MCE_PTYPE_L2_ETHTYPE (0b000110)
#define MCE_PTYPE_TUN_INNER_L2_ETHTYPE (0b000111)
#define MCE_PTYPE_IPV4_FRAG (0b001000)
#define MCE_PTYPE_IPV4_TCP_SYNC (0b001001)
#define MCE_PTYPE_IPV4_TCP (0b001010)
#define MCE_PTYPE_IPV4_UDP (0b001011)
#define MCE_PTYPE_IPV4_SCTP (0b001100)
#define MCE_PTYPE_IPV4_ESP (0b001101)
#define MCE_PTYPE_IPV4_UDP_ESP (0b001101)
#define MCE_PTYPE_IPV4_PAY (0b001110)

#define MCE_PTYPE_IPV6_FRAG (0b010000)
#define MCE_PTYPE_IPV6_TCP_SYNC (0b010001)
#define MCE_PTYPE_IPV6_TCP (0b010010)
#define MCE_PTYPE_IPV6_UDP (0b010011)
#define MCE_PTYPE_IPV6_SCTP (0b010100)
#define MCE_PTYPE_IPV6_ESP (0b010101)
#define MCE_PTYPE_IPV6_UDP_ESP (0b010101)
#define MCE_PTYPE_IPV6_PAY (0b010110)

#define MCE_PTYPE_TUN_INNER_IPV4_FRAG (0b101000)
#define MCE_PTYPE_TUN_INNER_IPV4_TCP_SYNC (0b101001)
#define MCE_PTYPE_TUN_INNER_IPV4_TCP (0b101010)
#define MCE_PTYPE_TUN_INNER_IPV4_UDP (0b101011)
#define MCE_PTYPE_TUN_INNER_IPV4_SCTP (0b101100)
#define MCE_PTYPE_TUN_INNER_IPV4_ESP (0b101101)
#define MCE_PTYPE_TUN_INNER_IPV4_UDP_ESP (0b101101)
#define MCE_PTYPE_TUN_INNER_IPV4_PAY (0b101110)

#define MCE_PTYPE_TUN_INNER_IPV6_FRAG (0b110000)
#define MCE_PTYPE_TUN_INNER_IPV6_TCP_SYNC (0b110001)
#define MCE_PTYPE_TUN_INNER_IPV6_TCP (0b110010)
#define MCE_PTYPE_TUN_INNER_IPV6_UDP (0b110011)
#define MCE_PTYPE_TUN_INNER_IPV6_SCTP (0b110100)
#define MCE_PTYPE_TUN_INNER_IPV6_ESP (0b110101)
#define MCE_PTYPE_TUN_INNER_IPV6_UDP_ESP (0b110101)
#define MCE_PTYPE_TUN_INNER_IPV6_PAY (0b110110)
#define MCE_PTYPE_TUN_IPV4_VXLAN (0b111000)
#define MCE_PTYPE_TUN_IPV4_GENEVE (0b111001)
#define MCE_PTYPE_TUN_IPV4_GRE (0b111010)
#define MCE_PTYPE_TUN_IPV6_VXLAN (0b111100)
#define MCE_PTYPE_TUN_IPV6_GENEVE (0b111101)
#define MCE_PTYPE_TUN_IPV6_GRE (0b111110)

/* inner options only valid gtp_u message_type is 0xff */
#define MCE_PTYPE_GTP_U_INNER_IPV4_FRAG (0b000100)
#define MCE_PTYPE_GTP_U_INNER_IPV4_PAY (0b011000)
#define MCE_PTYPE_GTP_U_INNER_IPV4_TCP (0b011001)
#define MCE_PTYPE_GTP_U_INNER_IPV4_UDP (0b011010)
#define MCE_PTYPE_GTP_U_INNER_IPV4_SCTP (0b011011)
#define MCE_PTYPE_GTP_U_INNER_IPV6_FRAG (0b000101)
#define MCE_PTYPE_GTP_U_INNER_IPV6_PAY (0b011100)
#define MCE_PTYPE_GTP_U_INNER_IPV6_TCP (0b011101)
#define MCE_PTYPE_GTP_U_INNER_IPV6_UDP (0b011110)
#define MCE_PTYPE_GTP_U_INNER_IPV6_SCTP (0b011111)

/* GTPv2 only valid GTP-C outer options */
#define MCE_PTYPE_GTP_U_GPDU_IPV4 (0b100000)
#define MCE_PTYPE_GTP_U_IPV4 (0b100001)
#define MCE_PTYPE_GTP_C_TEID_IPV4 (0b100010)
#define MCE_PTYPE_GTP_C_IPV4 (0b100011)

#define MCE_PTYPE_GTP_U_GPDU_IPV6 (0b100100)
#define MCE_PTYPE_GTP_U_IPV6 (0b100101)
#define MCE_PTYPE_GTP_C_TEID_IPV6 (0b100110)
#define MCE_PTYPE_GTP_C_IPV6 (0b100111)

#define __MCE_IPV4_HDR_DSCP_MASK (0xfc)
#define __MCE_IPV6_HDR_DSCP_MASK (0xfc)

enum mce_flow_params_error_type {
	MCE_FLOW_PARAMS_ERROR_ETH = 100,
	MCE_FLOW_PARAMS_ERROR_MAX,
};

enum mce_flow_item_type {
	MCE_FLOW_ITEM_TYPE_END,
	MCE_FLOW_ITEM_TYPE_VOID,
	MCE_FLOW_ITEM_TYPE_INVERT,
	MCE_FLOW_ITEM_TYPE_ANY,
	MCE_FLOW_ITEM_TYPE_PORT_ID,
	MCE_FLOW_ITEM_TYPE_RAW,
	MCE_FLOW_ITEM_TYPE_ETH,
	MCE_FLOW_ITEM_TYPE_VLAN,
	MCE_FLOW_ITEM_TYPE_IPV4,
	MCE_FLOW_ITEM_TYPE_IPV6,
	MCE_FLOW_ITEM_TYPE_ICMP,
	MCE_FLOW_ITEM_TYPE_UDP,
	MCE_FLOW_ITEM_TYPE_TCP,
	MCE_FLOW_ITEM_TYPE_SCTP,
	MCE_FLOW_ITEM_TYPE_VXLAN,
	MCE_FLOW_ITEM_TYPE_E_TAG,
	MCE_FLOW_ITEM_TYPE_NVGRE,
	MCE_FLOW_ITEM_TYPE_MPLS,
	MCE_FLOW_ITEM_TYPE_GRE,
	MCE_FLOW_ITEM_TYPE_FUZZY,
	MCE_FLOW_ITEM_TYPE_GTP,
	MCE_FLOW_ITEM_TYPE_GTPC,
	MCE_FLOW_ITEM_TYPE_GTPU,
	MCE_FLOW_ITEM_TYPE_ESP,
	MCE_FLOW_ITEM_TYPE_GENEVE,
	MCE_FLOW_ITEM_TYPE_VXLAN_GPE,
	MCE_FLOW_ITEM_TYPE_ARP_ETH_IPV4,
	MCE_FLOW_ITEM_TYPE_IPV6_EXT,
	MCE_FLOW_ITEM_TYPE_ICMP6,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_NS,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_NA,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_SLA_ETH,
	MCE_FLOW_ITEM_TYPE_ICMP6_ND_OPT_TLA_ETH,
	MCE_FLOW_ITEM_TYPE_MARK,
	MCE_FLOW_ITEM_TYPE_META,
	MCE_FLOW_ITEM_TYPE_GRE_KEY,
	MCE_FLOW_ITEM_TYPE_GTP_PSC,
	MCE_FLOW_ITEM_TYPE_PPPOES,
	MCE_FLOW_ITEM_TYPE_PPPOED,
	MCE_FLOW_ITEM_TYPE_PPPOE_PROTO_ID,
	MCE_FLOW_ITEM_TYPE_NSH,
	MCE_FLOW_ITEM_TYPE_IGMP,
	MCE_FLOW_ITEM_TYPE_AH,
	MCE_FLOW_ITEM_TYPE_HIGIG2,
	MCE_FLOW_ITEM_TYPE_TAG,
	MCE_FLOW_ITEM_TYPE_L2TPV3OIP,
	MCE_FLOW_ITEM_TYPE_PFCP,
	MCE_FLOW_ITEM_TYPE_ECPRI,
	MCE_FLOW_ITEM_TYPE_IPV6_FRAG_EXT,
	MCE_FLOW_ITEM_TYPE_GENEVE_OPT,
	MCE_FLOW_ITEM_TYPE_INTEGRITY,
	MCE_FLOW_ITEM_TYPE_CONNTRACK,
	MCE_FLOW_ITEM_TYPE_PORT_REPRESENTOR,
	MCE_FLOW_ITEM_TYPE_REPRESENTED_PORT,
	MCE_FLOW_ITEM_TYPE_FLEX,
	MCE_FLOW_ITEM_TYPE_L2TPV2,
	MCE_FLOW_ITEM_TYPE_PPP,
	MCE_FLOW_ITEM_TYPE_GRE_OPTION,
	MCE_FLOW_ITEM_TYPE_MACSEC,
	MCE_FLOW_ITEM_TYPE_METER_COLOR,
	MCE_FLOW_ITEM_TYPE_IPV4_FRAG_EXT,
	MCE_FLOW_ITEM_TYPE_MAX_NUM, /* 61 */
};

#define MCE_PARSE_ARFS_FLOW_ITERM_LOOKUP_LISTS                                \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) | BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) | BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP))

#define MCE_PARSE_FLOW_ITERM_LOOKUP_LISTS                                      \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) | BIT_ULL(MCE_FLOW_ITEM_TYPE_VLAN) |  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) | BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) | BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP) |   \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP) | BIT_ULL(MCE_FLOW_ITEM_TYPE_ESP))
#define MCE_PARSE_ENC_OUTER_FLOW_ITERM_LOOKUP_LISTS                           \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) | BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) | BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN) |                                  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE) |                                 \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE) |                                  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC) | BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU))
#define MCE_PARSE_ENC_INNER_FLOW_ITERM_LOOKUP_LISTS                           \
	(BIT_ULL(MCE_FLOW_ITEM_TYPE_ETH) | BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV4) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_IPV6) | BIT_ULL(MCE_FLOW_ITEM_TYPE_UDP) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_TCP) | BIT_ULL(MCE_FLOW_ITEM_TYPE_SCTP) | \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_VXLAN) |                                  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GENEVE) |                                 \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_NVGRE) |                                  \
	 BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPC) | BIT_ULL(MCE_FLOW_ITEM_TYPE_GTPU))
#if IS_ENABLED(CONFIG_NET_CLS_FLOWER)

struct mce_eswitch_filter;

enum mce_flow_module {
	MCE_FLOW_FDIR = 0,
	MCE_FLOW_ESWITCH,
	MCE_FLOW_MAX,
};

typedef int (*flow_engine_init_t)(struct mce_pf *pf, void **handle);
typedef void (*flow_engine_uinit_t)(struct mce_pf *pf,
				    enum mce_flow_module module);
typedef int (*flow_engine_create_t)(struct mce_pf *pf, void *p_filter,
				    struct mce_tc_flower_fltr *fltr);
typedef int (*flow_engine_destroy_t)(struct mce_pf *pf, void *p_filter,
				     struct mce_tc_flower_fltr *fltr);
typedef int (*flow_engine_query_t)(struct mce_pf *pf,
				   struct mce_tc_flower_fltr *fltr);
typedef int (*flow_engine_restore_t)(struct mce_pf *pf,
				     struct mce_tc_flower_fltr *fltr);
struct mce_flow_engine_module {
	flow_engine_init_t init; /* Init module manage resource info */
	flow_engine_uinit_t uinit; /* release all manage flow rule */
	// flow_engine_parse_t parse; /* check pattern hw can support */
	flow_engine_create_t create; /* create redirect flow action */
	flow_engine_destroy_t destroy; /* destroy the rule by add before */
	flow_engine_query_t query;
	flow_engine_restore_t restore;
	enum mce_flow_module type;
	void *handle;
};

#define MCE_ATR_BUCKET_HASH_KEY 0x3DAD14E2
#define MCE_ATR_SIGNATURE_HASH_KEY 0x174D3614

#define MCE_HASH_VALID_BIT GENMASK(11, 0)
#define MCE_SIGN_HASH_VALID_BIT GENMASK(15, 0)

#define MCE_FDIR_EXACT_ENTRAYS_BITS (12)
#define MCE_MAX_FDIR_EXACT_ENTRY BIT(MCE_FDIR_EXACT_ENTRAYS_BITS)
#define MCE_FDIR_SIGN_ENTRAYS_BITS (14)
#define MCE_MAX_FDIR_SIGN_ENTRY BIT(MCE_FDIR_SIGN_ENTRAYS_BITS)
#define MCE_NODE_MAX_ENTRY (4)
#define MCE_SIGN_NODE_MAX_ENTRY (4)
#define MCE_EXACT_NODE_MAX_ENTRY (2)

/* common all rule action bit define */
#define MCE_RULE_ACTION_DROP BIT(31)
#define MCE_RULE_ACTION_PASS (0)
#define MCE_RULE_ACTION_Q_EN BIT(30)
#define MCE_RULE_ACTION_VLAN_EN BIT(29)
#define MCE_RULE_ACTION_MARK_EN BIT(28)
#define MCE_RULE_ACTION_PRIO_EN BIT(27)
#define MCE_RULE_ACTION_Q_S (18)
#define MCE_RULE_ACTION_Q_MASK GENMASK(28, 18)
#define MCE_RULE_ACTION_POP_VLAN_MASK GENMASK(17, 16)
#define MCE_RULE_ACTION_POP_VLAN_S (16)
#define MCE_RULE_ACTION_MARK_MASK GENMASK(15, 0)

enum mce_pop_vlan_tag {
	MCE_POP_1VLAN = 1,
	MCE_POP_2VLAN,
	MCE_POP_3VLAN,
};

struct mce_inset_key {
	u64 inset_key0;
	u64 inset_key1;
} __packed __aligned(1);

struct mce_inset_key_extend {
	u32 dword_key[6];
} __packed __aligned(1);

struct mce_hw_inset_key {
	struct mce_inset_key inset;
	struct mce_inset_key_extend inset_ex;
	u32 dscp_vtag;
	u16 tun_type;
} __packed __aligned(1);

union mce_hash_data {
	struct {
		u32 hash_inset[10];
		u16 rev;
	};
	u16 word_stream[21];
} __packed __aligned(1);

union mce_ext_seg {
	struct {
		u16 first_seg : 15;
		u16 pad : 1;

		u16 data_1[21];
		u16 end_seg;
		/* 366 bit */
	};
	u16 word_stream[23];
} __packed __aligned(1);

struct mce_hash_key {
	u32 key[11];
} __packed __aligned(1);

/* Flow Director ATR input struct. */
union mce_exact_atr_input {
	struct {
		u16 next_fd_ptr : 13;
		u16 end : 1;
		u16 resv1 : 2;
		/* 16 bit */
		union {
			struct {
				u32 action;
				u16 priority : 3;
				u16 resv2 : 1;
				u16 e_vld : 1;
				u16 profile_id : 6;
				u16 resv3 : 5;
				u8 port : 7;
				u8 resv4 : 1;
				/* 56 bit */
				struct mce_inset_key inset;
				/* 184 bit */
			} __packed __aligned(1);
		} entry[MCE_EXACT_NODE_MAX_ENTRY];
		/* 384 bit */
	} v4;
	struct {
		u64 next_fd_ptr : 13;
		u64 end : 1;
		u64 action : 32;
		u64 priority : 3;
		u64 resv1 : 1;
		u64 e_vld : 1;
		u64 profile_id : 6;
		u64 port : 7;
		/* 64 bit */
		struct mce_inset_key inset;
		/* 192 bit */
		struct mce_inset_key_extend inset_ex;
		/* 384 bit */
	} v6;
	u32 dword_stream[12];
} __packed __aligned(1);

union mce_sign_atr_input {
	struct {
		u16 next_fd_ptr : 13;
		u16 end : 1;
		u16 resv1 : 2;
		/* 16 bit */
		struct {
			u32 actions;
			/* 32 bit */
			u32 priority : 3;
			u32 resv2 : 1;
			u32 resv3 : 4;
			u32 e_vld : 1;
			u32 profile_id : 6;
			u32 port : 7;
			u32 resv4 : 2;
			u32 sign_p1 : 8;
			/* 64 bit */
			u8 sign[3];
			/* 88 bit */
		} __packed __aligned(1) entry[MCE_SIGN_NODE_MAX_ENTRY];
		/* 192 bit */
	} __packed __aligned(1);
	u32 dword_stream[12];
} __packed __aligned(1);

enum mce_fdir_hash_mode {
	MCE_MODE_HASH_INSET,
	MCE_MODE_HASH_EX_PORT,
};

struct mce_node_key {
	union {
		/* exact_key */
		struct mce_hw_inset_key hw_inset;
		/* sign_key */
		u32 sign_hash;
	};
	bool used;
};

struct mce_node_info {
	struct mce_node_key key[MCE_NODE_MAX_ENTRY];

	u8 bit_used;
};

enum mce_fdir_mode_type {
	MCE_FDIR_EXACT_M_MODE,
	MCE_FDIR_SIGN_M_MODE,
	MCE_FDIR_EXACT_MACVLAN_MODE,
	MCE_FDIR_SIGN_MACVLAN_MODE,
	MCE_FDIR_MAX_MODE,
};

struct mce_fdir_node {
	struct list_head entry;
	enum mce_fdir_mode_type type;
	union mce_exact_atr_input exact_meta;
	union mce_sign_atr_input sign_meta;
	struct mce_node_info node_info;
	bool is_ipv6;
	u16 loc;
};

/* Flow Director ATR input struct. */
union mce_fdir_pattern {
	struct {
		union {
			struct {
				u8 src_mac[ETH_ALEN];
				u8 dst_mac[ETH_ALEN];
				u16 vlan_id;
			};
			struct {
				u16 ether_type;
				u32 dst_addr[4];
				u32 src_addr[4];
				u8 ip_tos;
				u8 protocol;
				u16 l4_sport;
				u16 l4_dport;
				union {
					u32 vni;
					u32 key;
					u32 esp_spi;
					u32 teid;
					u32 vtag; /* sctp vtag */
				};
				u16 tun_type;
			};
		};
	} __packed __aligned(1) formatted;
} __packed __aligned(1);

struct mce_hw_rule_inset {
	struct mce_hw_inset_key keys;

	u32 action;
	u8 profile_id;
	u8 port;
	u8 priority;
};

struct mce_rule_date {
	u32 dword_stream[12];
};

enum mce_filter_action {
	MCE_FILTER_PASS,
	MCE_FILTER_DROP,
};

struct mce_flow_action {
	u8 redirect_en;
	u8 mark_en;
	u8 pop_vlan;
	u8 rss_cfg;
	u8 priority;
	enum mce_filter_action rule_action;
};

enum flow_meta_type {
	MCE_ETH_META = 0,
	MCE_VLAN_META,
	MCE_IPV4_META,
	MCE_IPV6_META,
	MCE_IP_FRAG,
	MCE_UDP_META,
	MCE_TCP_META,
	MCE_SCTP_META,
	MCE_ESP_META,
	MCE_VXLAN_META,
	MCE_GENEVE_META,
	MCE_NVGRE_META,
	MCE_GTPU_META,
	MCE_GTPC_META,
	MCE_VPORT_ID,
	MCE_META_TYPE_MAX,
};

struct mce_ether_meta {
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];

	u16 ethtype_id;
};

struct mce_vlan_meta {
	u16 vlan_id;
};

struct mce_ipv4_meta {
	u32 src_addr;
	u32 dst_addr;
	u8 protocol;
	u8 is_frag;
	u8 dscp;
};

struct mce_ipv6_meta {
	u32 src_addr[4];
	u32 dst_addr[4];
	u8 protocol;
	u8 dscp;
	u8 is_frag;
};

struct mce_ip_frag_meta {
	u8 is_frag;
};

struct mce_tcp_meta {
	u16 src_port;
	u16 dst_port;
};

struct mce_udp_meta {
	u16 src_port;
	u16 dst_port;
};

struct mce_sctp_meta {
	u16 src_port;
	u16 dst_port;
	u32 vtag;
};

struct mce_esp_meta {
	u32 spi;
};

struct mce_vxlan_meta {
	u32 vni;
};

struct mce_geneve_meta {
	u32 vni;
};

struct mce_nvgre_meta {
	u32 key;
};

struct mce_gtp_meta {
	u32 teid; /**< Tunnel endpoint identifier. */
};

struct mce_vport_meta {
	u16 vport_id;
};

union mce_flow_hdr {
	struct mce_ether_meta eth_meta;
	struct mce_vlan_meta vlan_meta;
	struct mce_ipv4_meta ipv4_meta;
	struct mce_ipv6_meta ipv6_meta;
	struct mce_ip_frag_meta frag_meta;
	struct mce_tcp_meta tcp_meta;
	struct mce_udp_meta udp_meta;
	struct mce_sctp_meta sctp_meta;
	struct mce_esp_meta esp_meta;
	struct mce_vxlan_meta vxlan_meta;
	struct mce_geneve_meta geneve_meta;
	struct mce_nvgre_meta nvgre_meta;
	struct mce_gtp_meta gtp_meta;
	struct mce_vport_meta vport_meta;
};

struct mce_lkup_meta {
	enum flow_meta_type type;
	union mce_flow_hdr hdr;
	union mce_flow_hdr mask;
};

struct mce_flow_ptype_match {
	enum mce_flow_item_type *pattern_list;
	const u16 hw_type;
	const u64 insets;
};

#define MCE_ESW_MODE_LEGACY 0
#define MCE_ESW_MODE_SWITCHDEV 1

extern struct mce_flow_engine_module mce_fdir_engine;
extern struct mce_flow_engine_module mce_eswitch_engine;
#endif /* CONFIG_NET_CLS_FLOWER */

#endif /* _MCE_PATTERN_H_ */
