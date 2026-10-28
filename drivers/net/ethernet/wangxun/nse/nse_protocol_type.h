/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2018 - 2021 Beijing WangXun Technology Co., Ltd. */

#ifndef _NSE_PROTOCOL_TYPE_H_
#define _NSE_PROTOCOL_TYPE_H_
#include "nse_flex_type.h"
#define NSE_IPV6_ADDR_LENGTH 16

#define AMBER_627 0 /*1 means bug is existed*/

/* Each recipe can match up to 5 different fields. Fields to match can be meta-
 * data, values extracted from packet headers, or results from other recipes.
 */
#define NSE_NUM_WORDS_RECIPE 5

/* root recipe is not included, up to 5 sub recipes can be chained */
#define NSE_MAX_CHAIN_SUB_RECIPE 5

/* " + 1" means root recipe is included */
#define NSE_MAX_CHAIN_RECIPE (NSE_MAX_CHAIN_SUB_RECIPE + 1)

#define NSE_MAX_CHAIN_WORDS (NSE_NUM_WORDS_RECIPE * NSE_MAX_CHAIN_RECIPE)

/* max match lkup word from user = 25 words (50 bytes)*/
#define NSE_MAX_CHAIN_LKUP_WORDS (NSE_NUM_WORDS_RECIPE * NSE_MAX_CHAIN_SUB_RECIPE)

/* Field vector index corresponding to chaining */
#define NSE_CHAIN_FV_INDEX_START 47

/*software protocol type enum, not hardware protocol ID*/
enum nse_protocol_type {
	/* OF = Outer First
	 *  ILOS = Inner Last Or Single
	 *  IL = Inner Last
	 *  OLOS =  Outer Last Or Single
	 *  OFOS =  Outer First Or Single
	 */
	NSE_MAC_OFOS = 0,
	NSE_MAC_IL,
	NSE_ETYPE_OLOS,
	NSE_ETYPE_IL,
	NSE_VLAN_OFOS,
	NSE_IPV4_OFOS,
	NSE_IPV4_IL,
	NSE_IPV6_OFOS,
	NSE_IPV6_IL,
	NSE_IN_PORT,
	NSE_CT_STATE,
	NSE_FTE_ID,
	NSE_ZONE_ID,
	NSE_TCP_IL,
	NSE_UDP_OF,
	NSE_UDP_ILOS,
	NSE_SCTP_IL,
	NSE_VXLAN,
	NSE_GENEVE,
	NSE_VXLAN_GPE,
	NSE_NVGRE,
	NSE_GTP,
	NSE_GTP_NO_PAY,
	NSE_PPPOE,
	NSE_PFCP,
	NSE_L2TPV3,
	NSE_ESP,
	NSE_AH,
	NSE_NAT_T,
	NSE_VLAN_EX,
	NSE_VLAN_IN,
	NSE_FLG_DIR,
	NSE_PROTOCOL_LAST
};

enum nse_sw_tunnel_type {
	NSE_NON_TUN = 0,
	NSE_SW_TUN_AND_NON_TUN,
	NSE_SW_TUN_VXLAN_GPE,
	NSE_SW_TUN_GENEVE,      /* GENEVE matches only non-VLAN pkts */
	NSE_SW_TUN_GENEVE_VLAN, /* GENEVE matches both VLAN and non-VLAN pkts */
	NSE_SW_TUN_VXLAN,	/* VXLAN matches only non-VLAN pkts */
	NSE_SW_TUN_VXLAN_VLAN,  /* VXLAN matches both VLAN and non-VLAN pkts */
	NSE_SW_TUN_NVGRE,
	NSE_SW_TUN_UDP, /* This means all "UDP" tunnel types: VXLAN-GPE, VXLAN
			 * and GENEVE
			 */
	NSE_SW_IPV4_TCP,
	NSE_SW_IPV4_UDP,
	NSE_SW_IPV6_TCP,
	NSE_SW_IPV6_UDP,
	NSE_SW_TUN_IPV4_GTP_IPV4_TCP,
	NSE_SW_TUN_IPV4_GTP_IPV4_UDP,
	NSE_SW_TUN_IPV4_GTP_IPV6_TCP,
	NSE_SW_TUN_IPV4_GTP_IPV6_UDP,
	NSE_SW_TUN_IPV6_GTP_IPV4_TCP,
	NSE_SW_TUN_IPV6_GTP_IPV4_UDP,
	NSE_SW_TUN_IPV6_GTP_IPV6_TCP,
	NSE_SW_TUN_IPV6_GTP_IPV6_UDP,

	/* following adds support for GTP, just using inner protocols,
	 * outer L3 and L4 protocols can be anything
	 */
	NSE_SW_TUN_GTP_IPV4_TCP,
	NSE_SW_TUN_GTP_IPV4_UDP,
	NSE_SW_TUN_GTP_IPV6_TCP,
	NSE_SW_TUN_GTP_IPV6_UDP,
	NSE_SW_TUN_GTPU,
	NSE_SW_TUN_GTPC,
	NSE_SW_TUN_IPV4_GTPU_IPV4,
	NSE_SW_TUN_IPV4_GTPU_IPV6,
	NSE_SW_TUN_IPV6_GTPU_IPV4,
	NSE_SW_TUN_IPV6_GTPU_IPV6,
	NSE_SW_TUN_GTP_IPV4,
	NSE_SW_TUN_GTP_IPV6,
	NSE_ALL_TUNNELS /* All tunnel types including NVGRE */
};

/* Decoders for nse_prot_id:
 * - F: First
 * - I: Inner
 * - L: Last
 * - O: Outer
 * - S: Single
 */
enum nse_prot_id {
	NSE_PROT_ID_INVAL	= 0,
	NSE_PROT_MAC_OF_OR_S	= 1,
	NSE_PROT_MAC_O2		= 2,
	NSE_PROT_MAC_IL		= 4,
	NSE_PROT_MAC_IN_MAC	= 7,
	NSE_PROT_ETYPE_OL	= 9,
	NSE_PROT_ETYPE_IL	= 10,
	NSE_PROT_PAY		= 15,
	NSE_PROT_EVLAN_O	= 16,
	NSE_PROT_VLAN_O		= 17,
	NSE_PROT_VLAN_IF	= 18,
	NSE_PROT_MPLS_OL_MINUS_1 = 27,
	NSE_PROT_MPLS_OL_OR_OS	= 28,
	NSE_PROT_MPLS_IL	= 29,
	NSE_PROT_IPV4_OF_OR_S	= 32,
	NSE_PROT_IPV4_IL	= 33,
	NSE_PROT_IPV4_IL_IL	= 34,
	NSE_PROT_IPV6_OF_OR_S	= 40,
	NSE_PROT_IPV6_IL	= 41,
	NSE_PROT_IPV6_IL_IL	= 42,
	NSE_PROT_IPV6_NEXT_PROTO = 43,
	NSE_PROT_IPV6_FRAG	= 47,
	NSE_PROT_TCP_IL		= 49,
	NSE_PROT_UDP_OF		= 52,
	NSE_PROT_UDP_IL_OR_S	= 53,
	NSE_PROT_GRE_OF		= 64,
	NSE_PROT_NSH_F		= 84,
	NSE_PROT_ESP_F		= 88,
	NSE_PROT_ESP_2		= 89,
	NSE_PROT_SCTP_IL	= 96,
	NSE_PROT_ICMP_IL	= 98,
	NSE_PROT_ICMPV6_IL	= 100,
	NSE_PROT_VRRP_F		= 101,
	NSE_PROT_OSPF		= 102,
	NSE_PROT_PPPOE		= 103,
	NSE_PROT_L2TPV3		= 104,
	NSE_PROT_ECPRI		= 105,
	NSE_PROT_PPP		= 106,
	NSE_PROT_ATAOE_OF	= 114,
	NSE_PROT_CTRL_OF	= 116,
	NSE_PROT_LLDP_OF	= 117,
	NSE_PROT_ARP_OF		= 118,
	NSE_PROT_EAPOL_OF	= 120,
	NSE_PROT_META_ID	= 255, /* when offset == metaddata */
	NSE_PROT_INVALID	= 255  /* when offset == NSE_FV_OFFSET_INVAL */
};

#define NSE_VNI_OFFSET		12 /* offset of VNI from NSE_PROT_UDP_OF */

#define NSE_NAN_OFFSET		511

#define NSE_VLAN_OFOS_HW	121
#define NSE_VLAN_OL_HW		20
#define NSE_ETYPE_OLOS_HW	9
#define NSE_ETYPE_IL_HW		10
#define NSE_MAC_OFOS_HW		1
#define NSE_MAC_IL_HW		4
#define NSE_IPV4_OFOS_HW	32
#define NSE_IPV4_IL_HW		33
#define NSE_IPV6_OFOS_HW	40
#define NSE_IPV6_IL_HW		41
#define NSE_MD_PROT_HW		255
#define NSE_INPORT_MDID_HW	5
#define NSE_CT_STATE_MDID_HW 12
#define NSE_FTE_ID_MDID_HW	13
#define NSE_ZONE_ID_MDID_HW 14
#define NSE_TCP_IL_HW		49
#define NSE_UDP_ILOS_HW		53
#define NSE_ESP_HW			88
#define NSE_AH_HW			89
#define NSE_SCTP_IL_HW		96
#define NSE_PPPOE_HW		103
#define NSE_L2TPV3_HW		104

/* NSE_UDP_OF is used to identify all 3 tunnel types
 * VXLAN, GENEVE and VXLAN_GPE. To differentiate further
 * need to use flags from the field vector
 */
#define NSE_UDP_OF_HW	52 /* UDP Tunnels */
#define NSE_GRE_OF_HW	64 /* NVGRE */
#define NSE_PPPOE_HW	103
#define NSE_META_DATA_ID_HW 255 /* this is used for tunnel type */

#define NSE_MDID_SIZE 2
#define NSE_TUN_FLAG_MDID 20
#define NSE_TUN_FLAG_MDID_OFF(word) \
	(NSE_MDID_SIZE * (NSE_TUN_FLAG_MDID + (word)))
#define NSE_TUN_FLAG_MASK 0xFF
#define NSE_DIR_FLAG_MASK 0x10
#define NSE_TUN_FLAG_VLAN_MASK 0x01
#define NSE_TUN_FLAG_FV_IND 2

#define NSE_PROTOCOL_MAX_ENTRIES 16

/* Mapping of software defined protocol ID to hardware defined protocol ID */
struct nse_protocol_entry {
	enum nse_protocol_type type;
	u8 protocol_id;
};

struct nse_in_port {
	__be16 in_port;
};

struct nse_ct_state {
	__be16 ct_state;
};

struct nse_fte_id {
	__be16 fte_id;
};

struct nse_zone_id {
	__be16 zone;
};

struct nse_ether_hdr {
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];
};

struct nse_ethtype_hdr {
	__be16 ethtype_id;
};

struct nse_ether_vlan_hdr {
	u8 dst_addr[ETH_ALEN];
	u8 src_addr[ETH_ALEN];
	__be32 vlan_id;
};

struct nse_vlan_hdr {
	__be16 type;
	__be16 vlan;
};

struct nse_ipv4_hdr {
	u8 version;
	u8 tos;
	__be16 total_length;
	__be16 id;
	__be16 frag_off;
	u8 time_to_live;
	u8 protocol;
	__be16 check;
	__be32 src_addr;
	__be32 dst_addr;
};

struct nse_le_ver_tc_flow {
	union {
		struct {
			u32 flow_label : 20;
			u32 tc : 8;
			u32 version : 4;
		} fld;
		u32 val;
	} u;
};

struct nse_ipv6_hdr {
	__be32 be_ver_tc_flow;
	__be16 payload_len;
	u8 next_hdr;
	u8 hop_limit;
	u8 src_addr[NSE_IPV6_ADDR_LENGTH];
	u8 dst_addr[NSE_IPV6_ADDR_LENGTH];
};

struct nse_sctp_hdr {
	__be16 src_port;
	__be16 dst_port;
	__be32 verification_tag;
	__be32 check;
};

struct nse_l4_hdr {
	__be16 src_port;
	__be16 dst_port;

	union {
		struct {
			__be16 len;
			__be16 check;
		} udp;
		struct {
			__be32	seq;
			__be32	ack_seq;
			__be16	flags;
			__be16	window;
			__be16  check;
			__be16	urg_ptr;
		} tcp;
	};
};

struct nse_udp_tnl_hdr {
	__be16 field;
	__be16 proto_type;
	__be32 vni;	/* only use lower 24-bits */
};

struct nse_udp_gtp_hdr {
	u8 flags;
	u8 msg_type;
	__be16 rsrvd_len;
	__be32 teid;
	__be16 rsrvd_seq_nbr;
	u8 rsrvd_n_pdu_nbr;
	u8 rsrvd_next_ext;
	u8 rsvrd_ext_len;
	u8 pdu_type;
	u8 qfi;
	u8 rsvrd;
};
struct nse_pppoe_hdr {
	u8 rsrvd_ver_type;
	u8 rsrvd_code;
	__be16 session_id;
	__be16 length;
	__be16 ppp_prot_id; /* control and data only */
};

struct nse_pfcp_hdr {
	u8 flags;
	u8 msg_type;
	__be16 length;
	__be64 seid;
	__be32 seq;
	u8 spare;
};

struct nse_l2tpv3_sess_hdr {
	__be32 session_id;
	__be64 cookie;
};

struct nse_esp_hdr {
	__be32 spi;
	__be32 seq;
};

struct nse_ah_hdr {
	u8 next_hdr;
	u8 paylen;
	__be16 rsrvd;
	__be32 spi;
	__be32 seq;
};

struct nse_nat_t_hdr {
	struct nse_esp_hdr esp;
};

struct nse_nvgre {
	__be16 flags;
	__be16 protocol;
	__be32 tni_flow;
};

union nse_prot_hdr {
	struct nse_in_port in_port;
	struct nse_ct_state ct_state;
	struct nse_fte_id fte_id;
	struct nse_zone_id zone;
	struct nse_ether_hdr eth_hdr;
	struct nse_ethtype_hdr ethertype;
	struct nse_vlan_hdr vlan_hdr;
	struct nse_ipv4_hdr ipv4_hdr;
	struct nse_ipv6_hdr ipv6_hdr;
	struct nse_l4_hdr l4_hdr;
	struct nse_sctp_hdr sctp_hdr;
	struct nse_udp_tnl_hdr tnl_hdr;
	struct nse_nvgre nvgre_hdr;
	struct nse_udp_gtp_hdr gtp_hdr;
	struct nse_pppoe_hdr pppoe_hdr;
	struct nse_pfcp_hdr pfcp_hdr;
	struct nse_l2tpv3_sess_hdr l2tpv3_sess_hdr;
	struct nse_esp_hdr esp_hdr;
	struct nse_ah_hdr ah_hdr;
	struct nse_nat_t_hdr nat_t_hdr;
};

/* This is mapping table entry that maps every word within a given protocol
 * structure to the real byte offset as per the specification of that
 * protocol header.
 * for e.g. dst address is 3 words in ethertype header and corresponding bytes
 * are 0, 2, 3 in the actual packet header and src address is at 4, 6, 8
 */
struct nse_prot_ext_tbl_entry {
	enum nse_protocol_type prot_type;
	/* Byte offset into header of given protocol type */
	u8 offs[sizeof(union nse_prot_hdr)];
};

/* Extractions to be looked up for a given recipe */
struct nse_prot_lkup_ext {
	u16 prot_type;
	u8 n_val_words;
	/* create a buffer to hold max words per recipe */
	u16 field_off[NSE_MAX_CHAIN_WORDS];
	u16 field_mask[NSE_MAX_CHAIN_WORDS];

	struct nse_fv_word fv_words[NSE_MAX_CHAIN_WORDS];

	/* Indicate field offsets that have field vector indices assigned */
	DECLARE_BITMAP(done, NSE_MAX_CHAIN_WORDS);
};

struct nse_pref_lut_group {
	u8 n_val_pairs;		/* Number of valid pairs */
	struct nse_fv_word pairs[NSE_NUM_WORDS_RECIPE];
	u16 mask[NSE_NUM_WORDS_RECIPE];
};

struct nse_lut_grp_entry {
	struct list_head l_entry;

#define NSE_INVALID_RSLT_IDX 0xFF
	u16 lut_id;
	/* result index used by this intermediate recipe */
	u8  result_idx;
	u16 fv_idx[NSE_NUM_WORDS_RECIPE];
	u16 fv_mask[NSE_NUM_WORDS_RECIPE];
	struct nse_pref_lut_group lut_group;
};

/* fv list means profile entry, including fv cfg array*/
struct nse_sw_fv_list_entry {
	struct list_head list_entry;
	u16 profile_id;
	struct nse_fv *fv_ptr;
};

enum nse_prof_type {
	NSE_PROF_INVALID = 0x0,
	NSE_PROF_NON_TUN = 0x1,
	NSE_PROF_TUN_UDP = 0x2,
	NSE_PROF_TUN_GRE = 0x4,
	NSE_PROF_TUN_GTPU = 0x8,
	NSE_PROF_TUN_GTPC = 0x10,
	NSE_PROF_TUN_PPPOE = 0x20,
	NSE_PROF_TUN_ALL = 0x3E,
	NSE_PROF_ALL = 0xFF,
};

#endif /* _NSE_PROTOCOL_TYPE_H_ */
